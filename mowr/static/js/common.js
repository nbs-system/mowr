function search_sample() {
    /* TODO ADD SPINNING WHEEL */
    var query = $("#search-samples")[0].value;
    if (query.length < 2) {
        $("#search-result").html('');
        return;
    }
    $.ajax({
        url: "/common/search/" + query + "/f",
        success: function (result) {
            $("#search-result").html(result);
        }
    })
}
