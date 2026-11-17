(() => {
    const button = document.querySelector('#signout');
    const dialog = document.querySelector('#password-dialog');
    const form = document.querySelector('#password-form');
    const status = document.querySelector('#password-status');
    const save = document.querySelector('#save-password');
    document.querySelector('#change-password').addEventListener('click', () => { form.reset(); status.textContent = ''; dialog.showModal(); });
    document.querySelector('#cancel-password').addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => form.reset());
    form.addEventListener('submit', async event => {
        event.preventDefault();
        const currentPassword = document.querySelector('#current-password').value;
        const newPassword = document.querySelector('#new-password').value;
        const confirmPassword = document.querySelector('#confirm-password').value;
        if (newPassword !== confirmPassword) { status.textContent = 'The new passwords do not match.'; return; }
        save.disabled = true;
        status.textContent = 'Saving…';
        try {
            const response = await fetch('/auth/change-password', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ currentPassword, newPassword, confirmPassword }) });
            const result = await response.json();
            form.reset();
            status.textContent = result.message || 'Unable to change your password.';
            if (response.ok) location.replace('/login/?password-changed=1');
        } catch { status.textContent = 'Unable to connect. Please try again.'; }
        finally { save.disabled = false; }
    });
    button.addEventListener('click', async () => {
        button.disabled = true;
        try {
            const response = await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
            if (!response.ok) throw new Error('Sign out failed');
            location.replace('/login/');
        } catch {
            button.disabled = false;
            document.querySelector('#signout-status').textContent = 'Unable to sign out. Please try again.';
        }
    });
    // A restored tab must recheck the server session instead of showing cached tools.
    window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
})();
