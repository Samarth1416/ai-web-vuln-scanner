var ctx = document.getElementById("chart");

new Chart(ctx, {

type: "pie",

data: {

labels: ["SQL Injection","XSS","Safe"],

datasets: [{
data: [2,1,5],
backgroundColor: ["red","yellow","green"]
}]

}

});