function abc(){
    document.getElementById("para1").innerHTML='WE ARE LEARNING JS 1';
}
function showAlert(){
    window.alert('My first Alert Box!!!');
}

console.log('Hello');
console.log(12+343+34);
let name='ABC'
console.log('My name :',name)

let z=10;
console.log(z); //Global z
if (true){
    z=5
    console.log(z); //local
}
console.log(z); //global z
function f1(){
    var ab = 'some text'
    if (true){
        console.log(ab);
    }
}
f1(); //function calling
const pi = 3.14;
//pi = 23 //error




//creating a simple calculator using prompt
operator=prompt('Enter +,-,* or /');
let num1=parseFloat(prompt('Enter first number: '))
let num2=parseFloat(prompt('Enter second number:'))
if(operator=='+'){
    let ans = num1+num2;
    //console.log(`${num1} + ${num2} = ${ans}`)
    document.write(`${num1} + ${num2} = ${ans}`)
}
else if(operator=='-'){
    let ans = num1-num2;
    document.write(`${num1} - ${num2} = ${ans}`)
}
else if(operator=='*'){
    let ans = num1*num2;
    document.write(`${num1} * ${num2} = ${ans}`)
}
else if(operator=='/'){
    let ans = num1/num2;
    document.write(`${num1} / ${num2} = ${ans}`)
}
else{
    document.write('Enter a valid operator')
}

