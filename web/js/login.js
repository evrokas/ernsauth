// login.js — ErnsAuth login form enhancements
document.addEventListener('DOMContentLoaded', function() {
    // Auto-focus first empty input
    var inputs = document.querySelectorAll('input[type=text], input[type=password], input[type=email]');
    for (var i = 0; i < inputs.length; i++) {
        if (!inputs[i].value) {
            inputs[i].focus();
            break;
        }
    }
});
