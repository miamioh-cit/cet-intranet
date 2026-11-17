(() => {
    const button = document.querySelector('#signout');
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
