$(document).ready(function() {
	setInterval(function() {
		$.get("/recuperar_registros", function(data, status) {
			if (status == "success"){
			lista = "";
		for(var i=0; i< data.length; i++){
			lista += "<tr>"+"<td>"+data[i].Direccion+"</td>"+"<td>"+data[i].Estado+"</td>"+"<tr>"
			}
				$("#cambiar").html(lista);
			}
		});
	}, 1000) ;
});
