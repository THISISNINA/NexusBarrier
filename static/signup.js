/* Signup form behavior: strength meter, nickname placeholder, confirm check. */

var pwInput = document.getElementById("password");
var fill = document.getElementById("strength-fill");

function scorePassword(pw) {
  var score = 0;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return score;
}

pwInput.addEventListener("input", function () {
  var score = scorePassword(pwInput.value);
  var pct = (score / 4) * 100;
  fill.style.width = pct + "%";
  fill.style.background =
    score <= 1 ? "var(--red)" : score <= 2 ? "var(--amber)" : "var(--green)";
});

/* Nickname placeholder mirrors the server-side fallback (first name). */
var fullNameInput = document.getElementById("full_name");
var nicknameInput = document.getElementById("nickname");
fullNameInput.addEventListener("input", function () {
  var first = fullNameInput.value.trim().split(/\s+/)[0];
  nicknameInput.placeholder = first ? first : "e.g. Fatima";
});

document
  .getElementById("signup-form")
  .addEventListener("submit", function (e) {
    var pw = document.getElementById("password").value;
    var confirm = document.getElementById("password_confirm").value;
    if (pw !== confirm) {
      e.preventDefault();
      alert("Passwords don't match.");
    }
  });
