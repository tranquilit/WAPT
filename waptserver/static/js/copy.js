function copyToClipboard(element) {
	var $temp = $("<textarea>");
	$("body").append($temp);
	$temp.val($(element).text()).select();
	document.execCommand("copy");
	$temp.remove();
}