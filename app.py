import os
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, Response
from werkzeug.exceptions import HTTPException

from aml_service import AMLService
from aml_engine import AMLWorkflowManager, WorkflowError
import aml_pdf

base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, "templates")

app = Flask(__name__, template_folder=template_dir)
app.secret_key = os.urandom(24)
NO_SAR_CLOSURE_CODES = [
    "FALSE_POSITIVE",
    "LEGITIMATE_BUSINESS",
    "DATA_ERROR",
    "BELOW_REGULATORY_THRESHOLD",
    "MONITORING_ONLY",
]
SAR_CLOSURE_CODES = list(AMLService.SAR_CLOSURE_CODES)

def get_current_role():
    return session.get("role", "L1_ANALYST")

def get_current_user_id():
    return "MLRO_01" if get_current_role() == "MLRO" else "ANALYST_01"

@app.route("/switch-role", methods=["POST"])
def switch_role():
    new_role = request.form.get("role")
    if new_role in ["L1_ANALYST", "MLRO"]:
        session["role"] = new_role
    return redirect(request.referrer or url_for("alert_queue"))

@app.before_request
def _redirect_first_time_visitors_to_welcome():
    exempt_endpoints = {"welcome", "acknowledge_welcome", "static", "switch_role"}
    if request.endpoint in exempt_endpoints:
        return None
    if not session.get("seen_welcome"):
        return redirect(url_for("welcome"))
    return None

@app.route("/welcome")
def welcome():
    scenarios = AMLService.get_all_scenarios()
    return render_template("welcome.html", scenarios=scenarios, current_role=get_current_role())

@app.route("/welcome/continue", methods=["POST"])
def acknowledge_welcome():
    session["seen_welcome"] = True
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    summary = AMLService.get_dashboard_summary()
    return render_template("dashboard.html", summary=summary, current_role=get_current_role())

@app.route("/")
def alert_queue():
    role = get_current_role()
    if role == "MLRO":
        alerts = AMLService.get_open_and_escalated_alerts()
    else:
        alerts = AMLService.get_alerts_for_role(role)
    return render_template("alerts.html", alerts=alerts, current_role=role)

@app.route("/alerts/escalated")
def alert_queue_escalated():
    alerts = AMLService.get_alerts_for_role("MLRO")
    return render_template("alerts.html", alerts=alerts, show_escalated=True, current_role=get_current_role())

@app.route("/alerts/my-reviews")
def alert_queue_my_reviews():
    role = get_current_role()
    user_id = get_current_user_id()

    if role == "MLRO":
        all_alerts = AMLService.get_all_alerts()
        viewed_ids = AMLService.get_viewed_alert_ids(user_id)
        my_alerts = [
            a for a in all_alerts
            if a["alert_id"] in viewed_ids and a["status"] in ("UNDER_REVIEW", "ESCALATED")
        ]
    else:
        all_alerts = AMLService.get_all_alerts()
        my_alerts = [a for a in all_alerts if a["status"] == "UNDER_REVIEW"]

    return render_template("alerts.html", alerts=my_alerts, show_my_reviews=True, current_role=role)

@app.route("/alerts/all")
def alert_queue_all():
    alerts = AMLService.get_all_alerts()
    return render_template("alerts.html", alerts=alerts, show_all=True, current_role=get_current_role())

@app.route("/alert/<alert_id>")
def alert_detail(alert_id):
    alert = AMLService.get_alert(alert_id)
    if alert is None:
        abort(404)

    role = get_current_role()
    user_id = get_current_user_id()

    try:
        AMLService.log_alert_view(alert_id, user_id, role)
    except Exception:
        pass

    time_in_review = {}
    try:
        time_in_review = AMLService.get_time_in_review(alert_id)
    except Exception:
        pass

    rule_version = None
    try:
        rule_version = AMLService.get_rule_version_for_alert(alert_id)
    except Exception:
        pass

    customer = AMLService.get_customer_profile(alert.get("account_id") if isinstance(alert, dict) else alert[1])
    transactions = AMLService.get_alert_transactions(alert_id) or []
    decisions = AMLService.get_decision_history(alert_id) or []
    status = AMLService.get_alert_status(alert_id) or "OPEN"
    valid_next_states = AMLService.get_valid_next_states(alert_id) or []

    current_case = None
    try:
        current_case = AMLService.get_case_for_alert(alert_id)
    except Exception:
        pass

    related_alerts = []
    open_cases_for_account = []
    if current_case is None:
        try:
            related_alerts = AMLService.find_related_open_alerts(alert_id) or []
        except Exception:
            pass
        try:
            account_id = alert.get("account_id") if isinstance(alert, dict) else alert[1]
            open_cases_for_account = AMLService.get_open_cases_for_account(account_id) or []
        except Exception:
            pass

    return render_template(
        "alert_detail.html",
        alert=alert,
        customer=customer,
        transactions=transactions,
        decisions=decisions,
        status=status,
        valid_next_states=valid_next_states,
        no_sar_closure_codes=NO_SAR_CLOSURE_CODES,
        sar_closure_codes=SAR_CLOSURE_CODES,
        all_closure_codes=sorted(AMLWorkflowManager.VALID_CLOSURE_CODES),
        current_case=current_case,
        related_alerts=related_alerts,
        open_cases_for_account=open_cases_for_account,
        time_in_review=time_in_review,
        rule_version=rule_version,
        current_role=role
    )

@app.route("/claim/<alert_id>", methods=["POST"])
def claim_alert(alert_id):
    try:
        AMLService.claim_alert(alert_id, get_current_user_id(), get_current_role())
        try:
            AMLService.log_alert_view(alert_id, get_current_user_id(), get_current_role())
        except Exception:
            pass
        flash("Alert claimed.", "success")
    except WorkflowError as e: flash(str(e), "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/close/<alert_id>", methods=["POST"])
def close_alert(alert_id):
    try:
        AMLService.close_alert(alert_id, get_current_user_id(), request.form.get("narrative"), 
                               request.form.get("closure_reason_code"), request.form.get("sar_reference"), 
                               get_current_role())
        flash("Alert closed.", "success")
    except WorkflowError as e: flash(str(e), "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/escalate/<alert_id>", methods=["POST"])
def escalate_alert(alert_id):
    try:
        narrative = request.form.get("narrative", "")
        # Same 15-char floor as bulk escalation (see /bulk-action) and the
        # closure narrative check in transition_alert — the shared textarea
        # in alert_detail.html enforces this client-side via minlength="15",
        # but that's a UX nicety, not a security boundary; a direct POST
        # bypassing the browser must be rejected here too, server-side.
        if len(narrative.strip()) < 15:
            flash("A narrative of at least 15 characters is required to escalate.", "error")
            return redirect(url_for("alert_detail", alert_id=alert_id))
        AMLService.escalate_alert(alert_id, get_current_user_id(), get_current_role(), narrative=narrative)
        flash("Alert escalated.", "success")
    except WorkflowError as e: 
        flash(str(e), "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/return-to-analyst/<alert_id>", methods=["POST"])
def return_to_analyst(alert_id):
    try:
        AMLService.return_to_analyst(
            alert_id, get_current_user_id(), request.form.get("return_note"), get_current_role()
        )
        try:
            AMLService.log_alert_view(alert_id, get_current_user_id(), get_current_role())
        except Exception:
            pass
        flash("Alert returned to analyst for further review.", "success")
    except WorkflowError as e:
        flash(str(e), "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/bulk-action", methods=["POST"])
def bulk_action():
    action = request.form.get("action")
    alert_ids = request.form.getlist("alert_ids")
    narrative = request.form.get("narrative", "")

    if not alert_ids:
        flash("No alerts selected.", "error")
        return redirect(request.referrer or url_for("alert_queue"))

    if action not in ("claim", "escalate"):
        flash(f"Unsupported bulk action: {action}", "error")
        return redirect(request.referrer or url_for("alert_queue"))

    if action == "escalate" and len(narrative.strip()) < 15:
        flash("A narrative of at least 15 characters is required to bulk escalate.", "error")
        return redirect(request.referrer or url_for("alert_queue"))

    try:
        result = AMLService.bulk_transition(alert_ids, action, get_current_user_id(), get_current_role(), narrative=narrative)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(request.referrer or url_for("alert_queue"))

    succeeded, failed = result["succeeded"], result["failed"]
    if succeeded:
        flash(f"{len(succeeded)} alert(s) {action}ed successfully.", "success")
    if failed:
        detail = "; ".join(f"{aid[:8]}…: {reason}" for aid, reason in failed[:3])
        more = f" (+{len(failed) - 3} more)" if len(failed) > 3 else ""
        flash(f"{len(failed)} alert(s) failed: {detail}{more}", "error")

    return redirect(request.referrer or url_for("alert_queue"))

@app.route("/case/create/<alert_id>", methods=["POST"])
def create_case(alert_id):
    try:
        case_id = AMLService.create_case(alert_id)
        flash(f"Case created successfully: {case_id}", "success")
    except Exception as e:
        flash(f"Error creating case: {str(e)}", "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/case/<case_id>/link/<alert_id>", methods=["POST"])
def link_alert_to_case(case_id, alert_id):
    try:
        AMLService.link_alert_to_case(alert_id, case_id)
        flash("Alert linked to case.", "success")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        flash(f"Unexpected error: {e}", "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/case/<case_id>")
def case_detail(case_id):
    try:
        result = AMLService.get_case(case_id)
        if result is None:
            abort(404)
        return render_template("case_detail.html", case=result["case"], alerts=result["alerts"])
    except HTTPException:
        raise
    except Exception as e:
        flash(f"Error accessing case records: {e}", "error")
        return redirect(url_for("alert_queue"))

@app.route("/run-pipeline", methods=["POST"])
def run_pipeline():
    try:
        root_dir = os.path.dirname(os.path.abspath(__file__))
        subprocess.run(["python", "generator.py"], cwd=root_dir, check=True)
        subprocess.run(["python", "aml_loader.py"], cwd=root_dir, check=True)
        subprocess.run(["python", "aml_engine.py"], cwd=root_dir, check=True)
        flash("Data pipeline executed successfully! Workspace metrics updated.", "success")
    except Exception as e:
        flash(f"Pipeline Execution Failed: {str(e)}", "error")
    return redirect(request.referrer or url_for("alert_queue"))

@app.route("/reports")
def reports():
    return render_template("reports.html", report=AMLService.get_sla_report())

@app.route("/reports/export.pdf")
def export_sla_report_pdf():
    report = AMLService.get_sla_report()
    pdf_bytes = aml_pdf.render_sla_report_pdf(report)

    filename = f"aml_sla_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

if __name__ == "__main__":
    try:
        AMLService.ensure_db_ready()
    except Exception as e:
        print(f"Warning initializing DB schema mapping components: {e}")
    app.run(debug=True, host="127.0.0.1", port=5000)