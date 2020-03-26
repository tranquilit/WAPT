$(function(){
	$("#search-box").keyup(function(){
		$.ajax({
		type: "POST",
		url: "/store/search",
		data:'search='+$(this).val(),
		dataType:"json",
		beforeSend: function(){
			$("#search-box").css("background","#FFF no-repeat 165px");
		},
		success: function(data){
			$("#suggesstion-box").show();
			console.log(data);
			$("#suggesstion-box").html("");
			data.forEach(function(element) {
				var newSuggestion = document.createElement("div");
				newSuggestion.innerHTML = "<a class=\"dropdown-item\" href=\"/store/"+ element.package +"\">" + element.package + "</a>";
				document.querySelector("#suggesstion-box").appendChild(newSuggestion);
			});
			$("#search-box").css("background","#FFF");
		}
		});
	});
});

function selectCountry(val) {
$("#search-box").val(val);
$("#suggesstion-box").hide();
}