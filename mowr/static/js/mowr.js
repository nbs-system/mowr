function hashFile() {
    var file = $("#dropzone-file")[0].files[0];

    console.log(file);
    var reader = new FileReader();

    reader.onload = function() {
        var sha256 = CryptoJS.SHA256(reader.result);
        $.ajax({url: "/file/" + sha256, success: function(result) {
            console.log(result);

            if (result === "NOK") {
                // Upload the file
                $("#dropzone").submit();
            } else {
                // Do not upload the file
                window.location.replace('/file/' + result + '/choose')
            }
        }})
    };

    reader.onerror = function() {
        console.error("Could not read the file.");
    };

    reader.readAsBinaryString(file)
}