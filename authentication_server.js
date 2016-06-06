// =======================
// get the packages we need ============
// =======================

var express     = require('express');
var app         = express();
var bodyParser  = require('body-parser');
var morgan      = require('morgan');
var mongoose    = require('mongoose');

var jwt    = require('jsonwebtoken'); // used to create, sign, and verify tokens
var config = require('./config'); // get our config file
var User   = require('./app/models/user'); // get our mongoose model
    
// =======================
// configuration =========
// =======================
var port = process.env.PORT || 8078; // used to create, sign, and verify tokens
mongoose.connect(config.database); // connect to database
app.set('superSecret', config.secret); // secret variable

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

app.listen(port);
console.log('Started Authentication Server at http://localhost:' + port);

// get an instance of the router for api routes
var apiRoutes = express.Router(); 

// route to create a user (POST http://localhost:8078/authapi/createuser)
apiRoutes.post('/createuser', function(req, res) {

  // create a sample user
  var user = new User({ 
	userName:req.body.userName,
	email:req.body.email,
    password: req.body.password
  });

  // save the sample user
  user.save(function(err) {
    if (err) res.json({ success: false, message:err });

    console.log('User saved successfully');
    res.json({ success: true });
  });
});

// route to authenticate a user (POST http://localhost:8078/authapi/authenticate)
apiRoutes.post('/authenticate', function(req, res) {
  // find the user
  User.findOne({
    userName: req.body.userName
  }, function(err, user) {

    if (err) res.json({ success: false, message:err });

    if (!user) {
      res.json({ success: false, message: 'Authentication failed. User not found.' });
    } else if (user) {

      // check if password matches
      if (user.password != req.body.password) {
        res.json({ success: false, message: 'Authentication failed. Wrong password.' });
      } else {

        // if user is found and password is right
        // create a token
		var tokenPayload={};
		tokenPayload.id=user.id;
		tokenPayload.canAccessUserInfo=true;
        var token = jwt.sign(tokenPayload, app.get('superSecret'), {
          expiresIn: '24h' // expires in 24 hours
        });

        // return the information including token as JSON
        res.json({
          success: true,
          message: 'Success',
          token: token
        });
      }   

    }

  });
});

// route to get user info(POST http://localhost:8078/authapi/userinfo)
apiRoutes.get('/userinfo', function(req, res) {

  // check header or url parameters or post parameters for token
  var token = req.body.token || req.query.token || req.headers['x-access-token'];
  
  // decode token
  if (token) {

    // verifies secret and checks exp
    jwt.verify(token, app.get('superSecret'), function(err, decoded) {      
      if (err) {
        return res.json({ success: false, message: 'Failed to authenticate token.' });    
      } else {
		User.findById(decoded.id, function (err, user) {	

			if (err) {
				return res.json({ success: false, message: 'Failed to authenticate token.' });    
			} else{
				var userInfo={};				
				if(decoded.canAccessUserInfo)
				{
					userInfo.userName=user.userName;
					userInfo.email=user.email;
				}
				userInfo.success=true;
				res.json(userInfo);
			}	
		});
        
      }
    });

  } else {

    // if there is no token
    // return an error
    res.json({ success: false, message: 'Failed to authenticate token.' });   
  }
  

  
});
// apply the routes to our application with the prefix /api
app.use('/authapi', apiRoutes);
