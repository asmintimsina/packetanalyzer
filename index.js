var mysql      = require('mysql');
var http       = require('http');
var express    = require('express');
var bodyParser = require('body-parser');
var app        = express();
var httpServer = http.Server(app);
var router     = express.Router();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
var connection = mysql.createConnection({
  host     : 'localhost',
  user     : 'wireshark',
  password : 'wireshark',
  database : 'wiresharkAnalysis'
});

connection.connect(function(err) {
  if (err) {
    console.error('error connecting: ' + err.stack);
    return;
  }
  console.log('connected as id ' + connection.threadId);
});
router.get('/',function(req,res){
  return res.redirect('/dashboard');
});

router.get('/dashboard',function(req,res){
  return res.sendFile(__dirname + '/views/index.html');
});

router.get('/protocol',function(req,res){
  return res.sendFile(__dirname + '/views/protocol.html');
});

router.get('/source',function(req,res){
  return res.sendFile(__dirname + '/views/source.html');
});

router.get('/destination',function(req,res){
  return res.sendFile(__dirname + '/views/destination.html');
});

router.get('/api',function(req,res){
  var data = [];
  connection.query('SELECT Protocol, COUNT(*) AS Count FROM Wireshark GROUP BY Protocol ORDER BY COUNT(*) DESC;', function(err, rows) {
   //connected! (unless `err` is set)
   if(err){
     return res.status(400);
    }else{
      var temp = [];
      for(row in rows){
        var obj = {
          Protocol : rows[row].Protocol,
          count : rows[row].Count
        };
        temp.push(obj);
      }
      data.push(temp);
      //query Source
      connection.query('SELECT Source, COUNT(*) AS Count FROM Wireshark GROUP BY Source ORDER BY COUNT(*) DESC;', function(err, rows) {
        // connected! (unless `err` is set)
        if(err){
          return res.status(400);
        }else{
          var temp = [];
          for(row in rows){
            var obj = {
              Source : rows[row].Source,
              count : rows[row].Count
            };
            temp.push(obj);
          }
          data.push(temp);

          //query Destination
          connection.query('SELECT Destination, COUNT(*) AS Count FROM Wireshark GROUP BY Destination ORDER BY COUNT(*) DESC;', function(err, rows) {
            // connected! (unless `err` is set)
            if(err){
              return res.status(400);
            }else{
              var temp = [];
              for(row in rows){
                //console.log(rows[row]);
                var obj = {
                  Destination : rows[row].Destination,
                  count : rows[row].Count
                };
                temp.push(obj);
              }
              data.push(temp);
              //console.log(data);
              return res.status(200).send(data);
            }
          });
        }
      });
   }
  });
});

app.use('/',router);
app.use(express.static(__dirname+'/public'));

httpServer.listen(4000,function(){
  console.log('Server Listening at port 4000');
});