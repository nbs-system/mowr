function search_sample() {
    var query = $("#search-samples")[0].value;
    if (query.length < 2) {
        return;
    }
    $.ajax({
        url: "/admin/search/" + query + "/f",
        success: function (result) {
            $("#search-result").html(result);
        }
    })
}
