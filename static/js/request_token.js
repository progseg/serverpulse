document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('bttn_request_token').onclick = () => {
        let user_name = document.getElementById('user_name').value;
        let csrfToken = document.getElementsByName('csrfmiddlewaretoken')[0].value;
        document.getElementById('loading-message').hidden = false;
        
        fetch('request_token_admon_global', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({ user_name: user_name }),
        })
        .then(response => {
            if (response.ok) {
                alert('El token fue enviado con éxito');
            }
        })
        .finally(() => {
            document.getElementById('loading-message').hidden = true;
        });
    };
});