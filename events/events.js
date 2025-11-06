function func1(){
    document.getElementById("d1").classList.add("divclass");

}

function func2(){
    alert("A key is pressed");
    document.getElementById("p1").innerHTML="you are now typing";

}



//Objects

let car = "Nano"
 const car1 = {
    type:"Nano",
    color:"Yellow",
    model:"ABC"
 };

 document.write(car1.color+`<br>`);
 document.write(car1.type+`<br>`);
 document.write(car1["color"]);

 const person = {
    firstname: "SRINU",
    lastName: "SMITH",
    printName: function(){
      return this.firstname+" "+this.lastName  
    }
 }
 document.write(`<br>`)
 document.write(person.printName());
 let i;
 for(i in car1){
    document.write("<br>"+car1[i]);
 }