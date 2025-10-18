const { invoke } = window.__TAURI__.tauri;

document.addEventListener('DOMContentLoaded', () => {
    // Set Master Password
    document.getElementById('set-master-password').addEventListener('click', async () => {
        const password = document.getElementById('master-password').value;
        try {
            await invoke('set_master_password', { password });
            showStatus('Master password set successfully!', 'success');
        } catch (error) {
            showStatus('Error setting master password: ' + error, 'error');
        }
    });

    // Add Password
    document.getElementById('add-password').addEventListener('click', async () => {
        const account = document.getElementById('account-name').value;
        const password = document.getElementById('password').value;
        try {
            await invoke('add_password', { account, password });
            showStatus('Password added successfully!', 'success');
            document.getElementById('account-name').value = '';
            document.getElementById('password').value = '';
        } catch (error) {
            showStatus('Error adding password: ' + error, 'error');
        }
    });

    // View Password
    document.getElementById('view-password').addEventListener('click', async () => {
        const account = document.getElementById('view-account').value;
        try {
            const password = await invoke('get_password', { account });
            document.getElementById('password-display').textContent = `Password: ${password}`;
            showStatus('Password retrieved successfully!', 'success');
        } catch (error) {
            showStatus('Error retrieving password: ' + error, 'error');
            document.getElementById('password-display').textContent = '';
        }
    });

    // List Accounts
    document.getElementById('list-accounts').addEventListener('click', async () => {
        try {
            const accounts = await invoke('list_accounts');
            const list = document.getElementById('accounts-list');
            list.innerHTML = '';
            accounts.forEach(account => {
                const li = document.createElement('li');
                li.textContent = account;
                list.appendChild(li);
            });
            showStatus('Accounts listed successfully!', 'success');
        } catch (error) {
            showStatus('Error listing accounts: ' + error, 'error');
        }
    });

    // Generate OTP
    document.getElementById('generate-otp').addEventListener('click', async () => {
        const account = document.getElementById('otp-account').value;
        const username = document.getElementById('otp-username').value;
        const secret = document.getElementById('otp-secret').value;
        const length = parseInt(document.getElementById('otp-length').value);
        try {
            const otpPassword = await invoke('generate_otp', { account, username, secret, length });
            document.getElementById('otp-display').textContent = `Generated OTP: ${otpPassword}`;
            showStatus('OTP generated successfully!', 'success');
        } catch (error) {
            showStatus('Error generating OTP: ' + error, 'error');
            document.getElementById('otp-display').textContent = '';
        }
    });

    // Analyze Wi-Fi
    document.getElementById('analyze-wifi').addEventListener('click', async () => {
        try {
            const wifiPasswords = await invoke('analyze_wifi');
            const list = document.getElementById('wifi-list');
            list.innerHTML = '';
            wifiPasswords.forEach(([ssid, password, strength]) => {
                const li = document.createElement('li');
                li.textContent = `${ssid}: ${password} (${strength})`;
                list.appendChild(li);
            });
            showStatus('Wi-Fi analysis completed!', 'success');
        } catch (error) {
            showStatus('Error analyzing Wi-Fi: ' + error, 'error');
        }
    });
});

function showStatus(message, type) {
    const status = document.getElementById('status');
    status.textContent = message;
    status.className = `status ${type}`;
    setTimeout(() => {
        status.textContent = '';
        status.className = 'status';
    }, 5000);
}