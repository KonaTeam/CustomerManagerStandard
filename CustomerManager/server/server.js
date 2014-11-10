var express = require('express'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    session = require('express-session'),
    errorhandler = require('errorhandler'),
    csrf = require('csurf'),
    routes = require('./routes'),
    api = require('./routes/api'),
    DB = require('./accessDB'),
    protectJSON = require('./lib/protectJSON'),
    app = express();

app.use(session({ 
    secret: 'customermanagerstandard', 
    saveUninitialized: true,
    resave: true }));

app.set('views', __dirname + '/views');

// Kona Platform Integration

var request = require('request');

var kona_api_base = 'https://io.kona.com';

// These values come from Kona Accounts/Edit Account/Integrations
var kona_config = {
    callback_url: 'http://localhost:3000/callback'
    , clientID: '47f9bd054930ebacb19557bb40b54c432da22838fc417016185c469a56e7a71e'
    , clientSecret: '1059d0945bd16f35c85d30378b2ab8569b60349addaa344682ded66d9b741361'
}

var oauth2 = require('simple-oauth2')({
    clientID: kona_config.clientID,
    clientSecret: kona_config.clientSecret,
    site: kona_api_base
});

var authorization_uri = oauth2.authCode.authorizeURL({
    redirect_uri: kona_config.callback_url
});

app.get('/auth', function (req, res) {
    res.redirect(authorization_uri);
});

app.get('/callback', function (req, res) {
    oauth2.authCode.getToken({
        code: req.query.code,
        redirect_uri: kona_config.callback_url
    }, checkToken);

    function checkToken(error, result) {
        if (error) { 
            console.log('Access Token Error', error); 
            res.status(403).send('Not Authorized')
        }else{
            var token = oauth2.accessToken.create(result).token.access_token;

            req.session.token = token;

            // does that resolve to a user through the api?
            request({
                url: kona_api_base + '/api/userinfo',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                }
            }, function(error, response, body) {
                if (!error && response.statusCode == 200) {
                    req.session.user = JSON.parse(body).users[0];
                    // pass the user info to the client
                    res.cookie('user.id', req.session.user.id);
                    res.cookie('user.email', req.session.user.email);
                    res.cookie('user.token', req.session.token);
                    res.redirect('/');

                    console.log('Authenticated Kona User ID', req.session.user.id, 'email', req.session.user.email);
                }else{
                    res.status(403).send('Not Authorized')
                }
            });
        }
    }

});

app.all('*', function(req, res, next){
    if(typeof req.session.token === "undefined"){
        res.redirect('/auth');
    }else{
        next();
    }
});

//

app.set('view engine', 'jade');

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(__dirname + '/../'));
app.use(errorhandler());
app.use(protectJSON);
app.use(csrf());

app.use(function (req, res, next) {
    var csrf = req.csrfToken();
    res.cookie('XSRF-TOKEN', csrf);
    res.locals._csrf = csrf;
    next();
})

process.on('uncaughtException', function (err) {
    if (err) console.log(err, err.stack);
});

//Local Connection 
var conn = 'mongodb://localhost/customermanager';
var db = new DB.startup(conn);

// Routes
app.get('/', routes.index);

// JSON API
var baseUrl = '/api/dataservice/';

app.get(baseUrl + 'Customers', api.customers);
app.get(baseUrl + 'Customer/:id', api.customer);
app.get(baseUrl + 'CustomersSummary', api.customersSummary);
app.get(baseUrl + 'CustomerById/:id', api.customer);

app.post(baseUrl + 'PostCustomer', api.addCustomer);
app.put(baseUrl + 'PutCustomer/:id', api.editCustomer);
app.delete(baseUrl + 'DeleteCustomer/:id', api.deleteCustomer);

app.get(baseUrl + 'States', api.states);

app.get(baseUrl + 'CheckUnique/:id', api.checkUnique);

app.post(baseUrl + 'Login', api.login);
app.post(baseUrl + 'Logout', api.logout);


// redirect all others to the index (HTML5 history)
app.get('*', routes.index);

// Start server

app.listen(3000, function () {
    console.log("CustMgr Express server listening on port %d in %s mode", this.address().port, app.settings.env);
});
