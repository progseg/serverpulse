document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('bttn_request_token').addEventListener('click', async () => {
        let user_name = document.getElementById('user_name').value;
        let csrfToken = document.getElementsByName('csrfmiddlewaretoken')[0].value;
        document.getElementById('loading-message').hidden = false;

        try {
            const response = await fetch('request_token_admon_global', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken,
                },
                body: JSON.stringify({ user_name: user_name }),
            });

            if (response.ok) {
                const data = await response.json();
                if (data.message_type === 'success') {
                    alert('Éxito: ' + data.message);
                } else if (data.message_type === 'error') {
                    alert('Error: ' + data.message);
                }
            } else {
                throw new Error('Error en la solicitud');
            }
        } catch (error) {
            alert('Error en la solicitud: ' + error.message);
        } finally {
            document.getElementById('loading-message').hidden = true;
        }
    });
});