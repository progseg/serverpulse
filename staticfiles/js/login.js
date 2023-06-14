<script type="module">
window.addEventListener('beforeunload', (event) => {
  const confirmationMessage = '¿Estás seguro de que deseas abandonar la página, la sesión y el token se cancelarán?';
  event.returnValue = confirmationMessage;
  return
});
</script>
