package main

import (
	"database/sql"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"

	jwt "github.com/dgrijalva/jwt-go"
)

// User represents a client that can use the API.
type User struct {
	Username string
	Password string
	Profile  UserProfile
}

// UserProfile represents a public part of User information.
type UserProfile struct {
	Name        string   `json:"name"`
	Password    string   `json:"password"`
	Permissions []string `json:"permissions"`
}

// UserClaims is a set of JWT claims that contain UserProfile.
type UserClaims struct {
	Profile UserProfile `json:"profile"`
	jwt.StandardClaims
}

var signingKey = []byte("signing-key")

func signingKeyFn(*jwt.Token) (interface{}, error) {
	return signingKey, nil
}

var sampleUser = User{
	"cooldude",
	"weakpassword",
	UserProfile{Name: "James Smith", Permissions: []string{"doStuff"}},
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", login)
	http.HandleFunc("/read", read)
	http.HandleFunc("/home", homeHandler)

	log.Fatalln(http.ListenAndServe(":7777", nil))
}

func homeHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	data, err := ioutil.ReadFile("home.html")
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	fmt.Fprint(w, string(data))
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	data, err := ioutil.ReadFile("login.html")
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	fmt.Fprint(w, string(data))
}

func login(rw http.ResponseWriter, req *http.Request) {
	username := req.FormValue("username")
	password := req.FormValue("password")

	fmt.Println(username, " ", password)
	fmt.Println(checkUser(username, password))

	if checkUser(username, password) {
		// if username == sampleUser.Username && password == sampleUser.Password {
		// if checkUser(username,pass)
		expireToken := time.Now().Add(time.Hour * 1).Unix()
		claims := UserClaims{
			UserProfile{Name: username, Password: password, Permissions: []string{"doStuff"}},
			jwt.StandardClaims{
				Issuer:    "test-project",
				ExpiresAt: expireToken,
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString(signingKey)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte(err.Error()))
			log.Printf("err: %+v\n", err)
			return
		}

		// rw.WriteHeader(200)
		// printPage(rw, "home.html")

		// rw.Write([]byte(ss))
		// log.Printf("issued token: %v\n", ss)

		// Place the token in the client's cookie
		// Expires the token and cookie in 1 hour
		// expireToken := time.Now().Add(time.Hour * 1).Unix()
		expireCookie := time.Now().Add(time.Hour * 1)
		cookie := http.Cookie{Name: "Auth", Value: signedToken, Expires: expireCookie, HttpOnly: true}
		http.SetCookie(rw, &cookie)

		// Redirect the user to his profile
		http.Redirect(rw, req, "/home", 307)

		return
	}

	rw.WriteHeader(401)
	// printPage(rw,"sign")
	return
}

func printPage(rw http.ResponseWriter, fileName string) {
	//write to a file
	// rw.Header().Set("Content-Type", "text/html")
	// rw.WriteHeader(http.StatusOK)
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	// rw.Header().Set("Content-Length", fmt.Sprint(len(data)))
	// fmt.Fprint(rw, string(data))
	rw.Write([]byte(string(data)))
}

func read(rw http.ResponseWriter, req *http.Request) {
	var claims UserClaims

	cookie, err := req.Cookie("Auth")
	if err != nil {
		// http.NotFound(res, req)
		return
	}

	// token, err := jwtreq.ParseFromRequestWithClaims(req, jwtreq.AuthorizationHeaderExtractor, &claims, signingKeyFn)
	token, err := jwt.ParseWithClaims(cookie.Value, &claims, signingKeyFn)

	if err != nil {
		rw.WriteHeader(500)
		rw.Write([]byte("Failed to parse token"))
		log.Println("Failed to parse token")
		return
	}

	if !token.Valid {
		rw.WriteHeader(401)
		rw.Write([]byte("Invalid token"))
		log.Println("Invalid token")
		return
	}

	rw.WriteHeader(200)
	claimsString := fmt.Sprintf("claims: %v", claims)
	rw.Write([]byte(claimsString))
	log.Println("Successful", claimsString)
}

var db *sql.DB

func createDBconnection() {
	var err error

	db, err = sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/users")
	if err != nil {
		panic(err)
	}
}

func createAndUseDatabase(name string) {
	var err error

	_, err = db.Exec("CREATE DATABASE if not exists " + name)
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("USE " + name)
	if err != nil {
		panic(err)
	}
}
func createTable() {
	var err error
	_, err = db.Exec("CREATE TABLE user ( username varchar(30), password varchar(30) )")
	if err != nil {
		panic(err)
	}

}

func insertIntoTable(username string, password string) {
	// var err error
	// _, err = db.Exec("insert into user values('", username, "','", password, "')")
	db.Exec("INSERT INTO user(username, password) VALUES(?, ?)", username, password)
	// fmt.Println("insert into user values('", username, "','", username, "','", password, "')")
	// if err != nil {
	// 	panic(err)
	// }
}

type RESULTS struct {
	id       int
	name     string
	password string
}

func retrieveDetails() {
	var err error
	var results *sql.Rows
	results, err = db.Query("SELECT * from user")
	fmt.Println(reflect.TypeOf(results))

	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}

	for results.Next() {
		var res RESULTS
		err = results.Scan(&res.id, &res.name)
		if err != nil {
			panic(err.Error())
		}
		fmt.Println(res.id, " ", res.name)
	}

}

func checkUser(username string, password string) bool {
	createDBconnection()
	// var id int
	// var databaseUsername string
	// var databasePassword string

	var results *sql.Rows

	flag := false
	fmt.Println(username, " ", password)

	results, _ = db.Query("SELECT * from user where username=? and password=?", username, password)
	if results.Next() {
		var res RESULTS
		var err error
		err = results.Scan(&res.id, &res.name, &res.password)
		if err != nil {
			panic(err.Error())
		}

		if username == res.name && password == res.password {
			flag = true
		}
	}
	// for results.Next() {
	// 	var err error
	// 	err = results.Scan(id, databaseUsername, databasePassword)
	// 	if err != nil {
	// 		panic(err.Error())
	// 	}
	// 	fmt.Println(databaseUsername, " ", databasePassword)
	// 	if username == databaseUsername && password == databasePassword {
	// 		flag = true
	// 	}
	// }

	// // db.QueryRow("select username,password from user where username=?", username)
	// if username == databaseUsername && password == databasePassword {
	// 	flag = true
	// } else {
	// 	flag = false
	// }

	return flag
}
