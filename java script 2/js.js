for(let i=0;i<=10;i++){
    console.log(i);
}
a= parseInt(prompt('Enter a number to print table'));
for(let i=0;i<=10;i++){
    let res = a*i;
    document.write(`${a} * ${i} = ${res} <br>`);
}

b= parseInt(prompt('Enter a number'));
for(let j=0;j<=100;j++){
    let res = b+j;
    document.write(`${b} + ${j} = ${res} <br>`);
}
