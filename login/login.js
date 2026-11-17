(() => {
    const password = document.querySelector('#password');
    const toggle = document.querySelector('.show');
    const form = document.querySelector('#signin-form');
    const submit = document.querySelector('.submit');
    const message = document.querySelector('#preview-message');
    const showMessage = text => { message.hidden = false; message.textContent = text; };
    let permitted = location.protocol === 'https:';
    submit.disabled = true;
    fetch('/auth/options', { credentials: 'same-origin', cache: 'no-store' })
        .then(response => { if (!response.ok) throw new Error(); return response.json(); })
        .then(options => {
            permitted = permitted || options.allowHttp === true;
            submit.disabled = !permitted;
            if (!permitted) showMessage('Staff sign-in requires HTTPS. Please open the secure intranet address.');
        })
        .catch(() => showMessage('Sign-in is unavailable. Please try again shortly.'));
    toggle.addEventListener('click', () => {
        const show = password.type === 'password';
        password.type = show ? 'text' : 'password';
        toggle.textContent = show ? 'Hide' : 'Show';
        toggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
        toggle.setAttribute('aria-pressed', String(show));
    });
    form.addEventListener('submit', async event => {
        event.preventDefault();
        if (!permitted || submit.disabled) return;
        message.hidden = true;
        submit.disabled = true;
        submit.textContent = 'Signing in…';
        try {
            const response = await fetch('/auth/login', {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: document.querySelector('#username').value.trim(), password: password.value }),
            });
            password.value = '';
            const result = await response.json();
            if (!response.ok) { showMessage(result.message || 'Unable to sign in. Please try again.'); return; }
            location.replace('/admin/');
        } catch {
            password.value = '';
            showMessage('Unable to connect. Please try again.');
        } finally {
            submit.disabled = false;
            submit.textContent = 'Sign in →';
        }
    });
})();
