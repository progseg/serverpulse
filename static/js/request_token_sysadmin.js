document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('bttn_request_token').onclick = () => {
        let nickname = document.getElementById('nickname').value;
        let csrfToken = document.getElementsByName('csrfmiddlewaretoken')[0].value;

        document.getElementById('loading-message').hidden = false;
        fetch('request_token_sysadmin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({ nickname: nickname }),
        })
        .then(response => {
            if (response.ok) {
                alert('El token fue enviado con éxito');
            } else {
                alert('Ocurrió un error inesperado en el servidor, inténtelo de nuevo');
            }
        })
        .catch(error => {
            alert('Ocurrió un error inesperado al procesar la solicitud, inténtalo de nuevo');
        })
        .finally(() => {
            document.getElementById('loading-message').hidden = true;
        });
    };
});