var oktabaseURL = "https://login.vigneshl.com";
var request = new Array(5);
const app = document.getElementById("dashboard");
const container = document.createElement("div");
container.setAttribute("class", "rows");
app.appendChild(container);
// request[0] = new XMLHttpRequest()
// request[0].open('GET', 'https://www.cloudok.us/api/v1/users/me', true)
// request[0].withCredentials = true;
// request[0].onload = function() {
//   // Begin accessing JSON data here
//   var data = JSON.parse(this.response)
//   id=data
//   //console.log(request[0].status)
//
// if (request[0].status >= 200 && request[0].status < 400) {
//   document.getElementById('Name').innerHTML=data.profile.firstName + ' ' + data.profile.lastName
//   document.getElementById('Title').innerHTML=data.profile.title
// }}

//console.log(id)
request[1] = new XMLHttpRequest();
request[1].open("GET", oktabaseURL + "/api/v1/users/me/appLinks", true);
request[1].withCredentials = true;
request[1].onload = function () {
  var data1 = JSON.parse(this.response);
  for (var i in data1) {
    //const p = document.createElement('p')
    //user.lastName = user.lastName
    //p.textContent = data1.da
    //const an=document.createElement('a')
    const card = document.createElement("div");
    var elem = document.createElement("img");

    //request[2].onerror = function() {
    //  console.log("Error")

    //}
    //elem.addEventListener("error", (elem.src ="../default.png"));
    /*elem.onload = function() {
      alert(`Image loaded, size ${elem.width}x${elem.height}`);
    };



    var test=elem.onerror
    console.log(elem)
    console.dir(elem)

    //if (test==null) {
    //elem.src ="../default.png"
    //}
    */

    //card.setAttribute('class', "row row-cards")
    var str = data1[i].label;
    var result = str.link(data1[i].linkUrl);
    const h = "Link:" + "result";
    //h1.textContent = str.link(data1[i].linkUrl)
    const card1 = document.createElement("div");
    card1.setAttribute("class", "cards");
    card1.setAttribute("href", data1[i].linkUrl);

    // card.setAttribute("class", "col-6 col-sm-4 col-lg-2");
    //card.setAttribute =('href',result)
    const p = document.createElement("h4");
    p.textContent = str;

    //p.setAttribute("class","card-body p-3 text-center")
    //p.innerHTML = str
    container.appendChild(card1);
    card1.appendChild(card);
    card.appendChild(p);
    elem.src = data1[i].logoUrl;
    // console.log(elem.src);
    //elem.src ="../"  + data1[i].appName + ".png"
    //elem.setAttribute("height", "80%")
    //elem.setAttribute("width", "100%")

    var request = new XMLHttpRequest();
    request.open("GET", elem.src, false);
    request.send(null);

    if (request.status === 200) {
      card.appendChild(elem);
    } else {
      elem.src = "../default.png";
      card.appendChild(elem);
    }

    //document.getElementById("root1").appendChild(elem);
    i += 1;
  }
};
/*request.open('GET', 'https://www.cloudok.us/api/v1/users/'+id+'/applinks', true)
request.withCredentials = true;
request.onload = function() {
  // Begin accessing JSON data here
  var data1 = JSON.parse(this.response)
  console.log(data1)
if (request.status >= 200 && request.status < 400) {
  document.getElementById('test').innerHTML=data1.profile.firstName + ' ' + data1.profile.lastName
}
  /*
    //data.quotesArray.forEach(user => {
    for (var user in data) {
      console.log(user)
      console.log (user.profile)
      const card = document.createElement('div')
      card.setAttribute('class', 'card')

      const h1 = document.createElement('h1')
      h1.textContent = data.profile.firstName

      const p = document.createElement('p')
      //user.lastName = user.lastName
      p.textContent = data.profile.lastName

      container.appendChild(card)
      card.appendChild(h1)
      card.appendChild(p)
    }
  } else {
    const errorMessage = document.createElement('marquee')
    errorMessage.textContent = `Error!`
    app.appendChild(errorMessage)
  }
}*/
// request[0].send()

request[1].send();
