//practical 1

function validateForm(){
    let x=document.forms[0]["fname"].value;
    if (x=="") {
        alert("Name must be filled out ");
        return false;
    }
    let pwd=document.forms[0].txtPassword.value
    let cpwd=document.forms[0].txtConfirmPassword.value
    if (pwd==cpwd){
        return true;
    }
    else{
        alert("Please make sure that password and confirm password are same");
        return false;
    }
}


//practical 2
 
function ValidateMathFunction(){
    var FN = document.forms["form2"].txtFN.value;
    var SN = document.forms["form2"].txtSN.value
}
