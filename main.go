package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	// "net/http"
	"strconv"
	"time"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"github.com/gin-contrib/cors"
)


var (
	queryInsertUser     = "INSERT INTO user (name, email, password, gender, roles, image) VALUES (?, ?, ?, ?, ?, ?);"
	router = gin.Default()
	SecretKey = "qwe123"
)

func main() {
	Routers()
}

func Routers() {
	InitDB()
	defer db.Close()
	log.Println("Starting the HTTP server on port 9080")
	// router := mux.NewRouter()
	// router.HandleFunc("/post",
	// 	getPost).Methods("GET")
	// router.HandleFunc("/users",
	// 	getUser).Methods("GET")
	router.Use(cors.New(cors.Config{
			AllowOrigins:     []string{"http://localhost:3000"},
			AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
			AllowHeaders:     []string{"Content-Type"},
			ExposeHeaders:    []string{"Content-Length"},
			AllowCredentials: true,
			AllowOriginFunc: func(origin string) bool {
				return origin == "http://localhost:3000"
			},
			MaxAge: 12 * time.Hour,
		}))
	router.POST("/register", Register)
	router.POST("/login", Login)
	router.GET("/getExplore", getExplore)
	router.GET("/userList", getUserList)
	router.GET("/getStore", getStore)
	router.GET("/getComment", getComment)
	router.GET("/getTransaksi", getTransaksi)
	router.POST("/insertExplore", insertExplore)
	router.POST("/insertComment", insertComment)
	router.POST("/insertTransaksi", insertTransaksi)
	router.POST("/insertItem", insertItem)
	router.DELETE("/deleteExplore/:id", deleteExplore)
	router.DELETE("/deleteComment/:id", deleteComment)
	router.DELETE("/deleteStore/:id", deleteStore)
	router.PUT("/updateExplore/:id", updateExploreHandler)
	router.PUT("/updateUser/:id", updateUserHandler)
	router.PUT("/updateTransaksi/:id", updateTransaksi)
	router.PUT("/updateStore/:id", updateStoreHandler)
	
	router.Run(":8081")
	// router.HandleFunc("/users/{id}",
	// 	GetUser).Methods("GET")
	// router.HandleFunc("/users/{id}",
	// 	UpdateUser).Methods("PUT")
	// router.HandleFunc("/users/{id}",
	// 	DeleteUser).Methods("DELETE")
	// http.ListenAndServe(":9080",
	// 	&CORSRouterDecorator{router})
}

/***************************************************/
//Get all users

func Register(c *gin.Context) {
	var user User

	if err := c.ShouldBindJSON(&user); err != nil {
		err := NewBadRequestError("invalid json body")
		c.JSON(err.Status, err)
		return
	}

	result, saveErr := CreateUser(user)
	if saveErr != nil {
		c.JSON(saveErr.Status, saveErr)
		return
	}

	c.JSON(http.StatusOK, result)
}



func CreateUser(user User) (*User, *RestErr) {
	if err := user.Validate(); err != nil {
		return nil, err
	}

	// encrpyt the password
	pwSlice, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	if err != nil {
		return nil, NewBadRequestError(("failed to encrypt the password"))
	}

	user.Password = string(pwSlice[:])

	if err := user.Save(); err != nil {
		return nil, err
	}

	return &user, nil

}

func (user *User) Save() *RestErr {
	stmt, err := db.Prepare(queryInsertUser)
	if err != nil {
		return NewInternalServerError("database error")
	}
	defer stmt.Close()

	insertResult, saveErr := stmt.Exec(user.Name, user.Email, user.Password, user.Gender, user.Roles, user.Image)
	if saveErr != nil {
		fmt.Println(saveErr)
		return NewInternalServerError("database error")
	}

	userID, err := insertResult.LastInsertId()
	if err != nil {
		return NewInternalServerError("database error")
	}
	user.ID = userID
	return nil
}

func (user *User) Validate() *RestErr {
	user.Name = strings.TrimSpace(user.Name)
	user.Email = strings.TrimSpace(user.Email)
	if user.Email == "" {
		return NewBadRequestError("invalid email address")
	}

	user.Password = strings.TrimSpace(user.Password)
	if user.Password == "" {
		return NewBadRequestError("invalid password")
	}
	return nil
}




// FOR LOGIN
func Login(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		err := NewBadRequestError("invalid json")
		c.JSON(err.Status, err)
		return
	}
	fmt.Println(user)

	result, getErr := GetUser(user)
	if getErr != nil {
		c.JSON(getErr.Status, getErr)
		return
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    strconv.Itoa(int(result.ID)),
		ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
	})

	token, err := claims.SignedString([]byte(SecretKey))
	if err != nil {
		err := NewInternalServerError("login failed")
		c.JSON(err.Status, err)
		return
	}

	c.SetCookie("jwt", token, 3600, "/", "localhost", false, true)

	c.JSON(http.StatusOK, result)
}

func GetUser(user User) (*User, *RestErr) {
	result := &User{Email: user.Email}

	if err := result.GetByEmail(); err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password)); err != nil {
		return nil, NewBadRequestError("failed to decrypt the password")
	}

	resultWp := &User{ID: result.ID, Name: result.Name, Email: result.Email, Password: result.Password, Gender : result.Gender, Roles: result.Roles, Image : result.Image}
	return resultWp, nil
}


func (user *User) GetByEmail() *RestErr {
	stmt, err := db.Prepare("SELECT * FROM user WHERE email=?;")
	if err != nil {
		return NewInternalServerError("invalid email")
	}
	defer stmt.Close()

	result := stmt.QueryRow(user.Email)
	if getErr := result.Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Gender, &user.Roles, &user.Image); getErr != nil {
		fmt.Println(getErr)
		return NewInternalServerError("database error")
	}
	return nil
}


func getExplore(c *gin.Context) {
	code := c.Param("code")

	posting := getExploreData(code)

	if posting == nil {
		c.AbortWithStatus(http.StatusNotFound)
	} else {
		c.IndentedJSON(http.StatusOK, posting)
	}
}

func getExploreData(code string) []Postingan {

	var posts []Postingan
	result, err := db.Query("SELECT * FROM posting ORDER BY id DESC")

	if err != nil {
		fmt.Println("Err", err.Error())
		return nil
	}

	for result.Next() {
		var postingan Postingan
		err := result.Scan(&postingan.ID, &postingan.User_id,
			&postingan.Title, &postingan.Post, &postingan.Gambar, &postingan.Date)
		if err != nil {
			panic(err.Error())
		}
		posts = append(posts, postingan)
	}

	return posts
}


func deleteExplore(c *gin.Context) {
	id := c.Param("id")
	itemID, err := strconv.Atoi(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	err = deteteExploreDB(itemID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Item deleted successfully"})
}

func deteteExploreDB(id int) error {
	
	_, err = db.Exec("DELETE FROM posting WHERE id = ?", id)
	if err != nil {
		return err
	}

	return nil
}


func deleteStore(c *gin.Context) {
	id := c.Param("id")
	itemID, err := strconv.Atoi(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	err = deleteStoreDB(itemID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Item deleted successfully"})
}

func deleteStoreDB(id int) error {
	
	_, err = db.Exec("DELETE FROM store WHERE id = ?", id)
	if err != nil {
		return err
	}

	return nil
}

func deleteComment(c *gin.Context) {
	id := c.Param("id")
	itemID, err := strconv.Atoi(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	err = deleteCommentDB(itemID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Item deleted successfully"})
}

func deleteCommentDB(id int) error {
	
	_, err = db.Exec("DELETE FROM comment WHERE id = ?", id)
	if err != nil {
		return err
	}
	return nil
}




func getUserList(c *gin.Context) {
	code := c.Param("code")

	userListData := getUserListData(code)

	if userListData == nil {
		c.AbortWithStatus(http.StatusNotFound)
	} else {
		c.IndentedJSON(http.StatusOK, userListData)
	}
}

func getUserListData(code string) []UserData {

	var users []UserData
	result, err := db.Query("SELECT id, name, email, gender, roles, image FROM user ")

	if err != nil {
		fmt.Println("Err", err.Error())
		return nil
	}

	for result.Next() {
		var user UserData
		err := result.Scan(&user.ID, &user.Name,
			&user.Email, &user.Gender, &user.Roles, &user.Image)
		if err != nil {
			panic(err.Error())
		}
		users = append(users, user)
	}

	return users
}

func insertExplore(c *gin.Context) {
	var post Postingan
	
	if err := c.ShouldBindJSON(&post); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
	} else {
		addExplore(post)
		c.IndentedJSON(http.StatusCreated, post)
	}
}

func addExplore(post Postingan) {

	insert, err := db.Query(
		"INSERT INTO posting (user_id, title, post, gambar, date) VALUES (?,?,?,?,?)",
		post.User_id, post.Title, post.Post, post.Gambar, post.Date)

	// if there is an error inserting, handle it
	if err != nil {
		panic(err.Error())
	}

	defer insert.Close()
}

func updateExploreHandler(c *gin.Context) {
	id := c.Param("id")

	var data UpdatePostingan
	if err := c.BindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := updateDataExplore(id, data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data updated successfully"})
}

func updateDataExplore(id string, data UpdatePostingan) error {
	query := `UPDATE posting SET title = ?, post = ?, gambar = ? WHERE id = ?`
	_, err = db.Exec(query, data.Title, data.Post, data.Gambar, id)
	if err != nil {
		return err
	}
	return nil
}



func updateStoreHandler(c *gin.Context) {
	id := c.Param("id")

	var data Store
	if err := c.BindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := updateDataStore(id, data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data updated successfully"})
}

func updateDataStore(id string, data Store) error {
	fmt.Println(id)
	fmt.Println(data.Title)
	fmt.Println(data.Desc)
	fmt.Println(data.Image)
	fmt.Println(data.Price)
	query := "UPDATE `store` SET `title` = ?, `desc` = ?, `image` = ?, `price` = ?  WHERE `store`.`id` = ?;"
	_, err = db.Exec(query, data.Title, data.Desc, data.Image, data.Price, id)
	if err != nil {
		return err
	}
	return nil
}


func updateTransaksi(c *gin.Context) {
	id := c.Param("id")

	var data Transaksi
	if err := c.BindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := updateTransaksiHandler(id, data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data updated successfully"})
}

func updateTransaksiHandler(id string, data Transaksi) error {
	query := `UPDATE transaksi SET process = ? WHERE id = ?`
	_, err = db.Exec(query, data.Process, id)
	if err != nil {
		return err
	}
	return nil
}

func updateUserHandler(c *gin.Context) {
	id := c.Param("id")

	var userData UserUpdateData
	if err := c.BindJSON(&userData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := updateDataUser(id, userData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data updated successfully"})
}

func updateDataUser(id string, data UserUpdateData) error {
	query := `UPDATE user SET email = ?, name = ?, image= ? WHERE id = ?`
	_, err = db.Exec(query, data.Email, data.Name, data.Image, id)
	if err != nil {
		return err
	}
	return nil
}


func insertComment(c *gin.Context) {
	var comment Comment
	
	if err := c.ShouldBindJSON(&comment); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
	} else {
		addComment(comment)
		c.IndentedJSON(http.StatusCreated, comment)
	}
}

func addComment(comment Comment) {

	insert, err := db.Query(
		"INSERT INTO comment (user_id, post_id, comment, date) VALUES (?,?,?,?)",
		comment.User_id, comment.Post_id, comment.Comment, comment.Date)

	// if there is an error inserting, handle it
	if err != nil {
		panic(err.Error())
	}

	defer insert.Close()
}


func insertItem(c *gin.Context) {
	var store Store
	
	if err := c.ShouldBindJSON(&store); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
	} else {
		addItem(store)
		c.IndentedJSON(http.StatusCreated, store)
	}
}

func addItem(store Store) {
	fmt.Println(string(store.Title))
	fmt.Println(string(store.Desc))
	fmt.Println(store.User_id)
	fmt.Println(string(store.Image))
	fmt.Println(store.Date)
	fmt.Println(store.Price)
	insert, err := db.Query(
		"INSERT INTO `store` (`id`, `title`, `desc`, `user_id`, `image`, `date`, `price`) VALUES (NULL, ?,?,?,?,?,?)",
		store.Title, store.Desc, store.User_id, store.Image, store.Date, store.Price)

	if err != nil {
		panic(err.Error())
	}

	defer insert.Close()
}

func insertTransaksi(c *gin.Context) {
	var transaksi Transaksi
	
	if err := c.ShouldBindJSON(&transaksi); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
	} else {
		addTransaksi(transaksi)
		c.IndentedJSON(http.StatusCreated, transaksi)
	}
}

func addTransaksi(transaksi Transaksi) {

	insert, err := db.Query(
		"INSERT INTO transaksi (user_id, item_id, quantity, process, date) VALUES (?,?,?,?, ?)",
		transaksi.User_id, transaksi.Item_id, transaksi.Quantity, transaksi.Process, transaksi.Date)

	if err != nil {
		panic(err.Error())
	}

	defer insert.Close()
}


func getStore(c *gin.Context) {
	code := c.Param("code")

	store := getStoreData(code)

	if store == nil {
		c.AbortWithStatus(http.StatusNotFound)
	} else {
		c.IndentedJSON(http.StatusOK, store)
	}
}

func getStoreData(code string) []Store {
	var stores []Store
	result, err := db.Query("SELECT * FROM store ORDER BY id DESC")

	if err != nil {
		fmt.Println("Err", err.Error())
		return nil
	}

	for result.Next() {
		var store Store
		err := result.Scan(&store.ID, &store.Title, &store.Desc, &store.User_id, &store.Image, &store.Date, &store.Price)
		if err != nil {
			panic(err.Error())
		}
		stores = append(stores, store)
	}

	return stores
}

func getTransaksi(c *gin.Context) {
	code := c.Param("code")

	transaksi := getTransaksiData(code)

	if transaksi == nil {
		c.AbortWithStatus(http.StatusNotFound)
	} else {
		c.IndentedJSON(http.StatusOK, transaksi)
	}
}

func getTransaksiData(code string) []Transaksi {
	var listTransaksi []Transaksi
	result, err := db.Query("SELECT * FROM transaksi ORDER BY id DESC")

	if err != nil {
		fmt.Println("Err", err.Error())
		return nil
	}

	for result.Next() {
		var transaksi Transaksi
		err := result.Scan(&transaksi.ID, &transaksi.User_id, &transaksi.Item_id, &transaksi.Quantity, &transaksi.Process, &transaksi.Date)
		if err != nil {
			panic(err.Error())
		}
		listTransaksi = append(listTransaksi, transaksi)
	}

	return listTransaksi
}
func getComment(c *gin.Context) {
	code := c.Param("code")
	comment := getCommentData(code)
	if comment == nil {
		c.AbortWithStatus(http.StatusNotFound)
	} else {
		c.IndentedJSON(http.StatusOK, comment)
	}
}

func getCommentData(code string) []Comment {
	var comments []Comment
	result, err := db.Query("SELECT * FROM comment ORDER BY id DESC")

	if err != nil {
		fmt.Println("Err", err.Error())
		return nil
	}

	for result.Next() {
		var comment Comment
		err := result.Scan(&comment.ID, &comment.User_id, &comment.Post_id, &comment.Comment, &comment.Date)
		if err != nil {
			panic(err.Error())
		}
		comments = append(comments, comment)
	}

	return comments
}


func getPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var posts []Postingan
	result, err := db.Query("SELECT * from posting");
	if err != nil {
		panic(err.Error())
	}
	defer result.Close()
	for result.Next() {
		var postingan Postingan
		err := result.Scan(&postingan.ID, &postingan.User_id,
			&postingan.Title, &postingan.Post, &postingan.Gambar, &postingan.Date)
		if err != nil {
			panic(err.Error())
		}
		posts = append(posts, postingan)
	}
	json.NewEncoder(w).Encode(posts)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var users []User
	result, err := db.Query("SELECT * from user");
	if err != nil {
		panic(err.Error())
	}
	defer result.Close()
	for result.Next() {
		var user User
		err := result.Scan(&user.ID, &user.Name,
			&user.Email, &user.Password, &user.Gender, &user.Roles, &user.Image)
		if err != nil {
			panic(err.Error())
		}
		users = append(users, user)
	}
	json.NewEncoder(w).Encode(users)
}
//Create user
// func CreateUser(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	stmt, err := db.Prepare("INSERT INTO users(first_name," +
// 		"last_name,email) VALUES(?,?,?)")
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	body, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	keyVal := make(map[string]string)
// 	json.Unmarshal(body, &keyVal)
// 	first_name := keyVal["firstName"]
// 	last_name := keyVal["lastName"]
// 	email := keyVal["email"]
// 	_, err = stmt.Exec(first_name, last_name, email)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	fmt.Fprintf(w, "New user was created")
// }

//Get user by ID
// func GetUser(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	params := mux.Vars(r)
// 	result, err := db.Query("SELECT id, first_name,"+
// 		"last_name,email from users WHERE id = ?", params["id"])
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	defer result.Close()
// 	var user User
// 	for result.Next() {
// 		err := result.Scan(&user.ID, &user.FirstName,
// 			&user.LastName, &user.Email)
// 		if err != nil {
// 			panic(err.Error())
// 		}
// 	}
// 	json.NewEncoder(w).Encode(user)
// }

//Update user
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	stmt, err := db.Prepare("UPDATE users SET first_name = ?," +
		"last_name= ?, email=? WHERE id = ?")
	if err != nil {
		panic(err.Error())
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err.Error())
	}
	keyVal := make(map[string]string)
	json.Unmarshal(body, &keyVal)
	first_name := keyVal["firstName"]
	last_name := keyVal["lastName"]
	email := keyVal["email"]
	_, err = stmt.Exec(first_name, last_name, email,
		params["id"])
	if err != nil {
		panic(err.Error())
	}
	fmt.Fprintf(w, "User with ID = %s was updated",
		params["id"])
}

//Delete User
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	stmt, err := db.Prepare("DELETE FROM users WHERE id = ?")
	if err != nil {
		panic(err.Error())
	}
	_, err = stmt.Exec(params["id"])
	if err != nil {
		panic(err.Error())
	}
	fmt.Fprintf(w, "User with ID = %s was deleted",
		params["id"])
}

/***************************************************/

type Postingan struct {
	ID        int64 `json:"id"`
	User_id int64 `json:"user_id"`
	Title  string `json:"title"`
	Post     string `json:"post"`
	Gambar     string `json:"gambar"`
	Date     int64 `json:"date"`
}

type UpdatePostingan struct {
	Title  string `json:"title"`
	Post     string `json:"post"`
	Gambar     string `json:"gambar"`
}

type Comment struct {
	ID        int64 `json:"id"`
	User_id int64 `json:"user_id"`
	Post_id  int64 `json:"post_id"`
	Comment     string `json:"comment"`
	Date     int64 `json:"date"`
}

type Store struct{
	ID int `json:"id"`
	Title string `json:"title"`
	Desc string `json:"desc"`
	User_id int64 `json:"user_id"`
	Image string `json:"image"`
	Date int64 `json:"date"`
	Price int64 `json:"price"`
}

type User struct {
	ID        int64 `json:"id"`
	Name string `json:"name"`
	Email  string `json:"email"`
	Password     string `json:"password"`
	Gender string `json:"gender"`
	Roles     int `json:"roles"`
	Image string `json:"image"`
}

type UserUpdateData struct {
	Name string `json:"name"`
	Email  string `json:"email"`
	Image string `json:"image"`
}


type UserData struct {
	ID        int64 `json:"id"`
	Name string `json:"name"`
	Email  string `json:"email"`
	Gender string `json:"gender"`
	Roles     int `json:"roles"`
	Image string `json:"image"`
}

type Transaksi struct {
	ID        int64 `json:"id"`
	User_id int64 `json:"user_id"`
	Item_id  int64 `json:"item_id"`
	Quantity int64 `json:"quantity"`
	Process     int64 `json:"process"`
	Date int64 `json:"date"`
}

//Db configuration
var db *sql.DB
var err error

func InitDB() {
	db, err = sql.Open("mysql",
		"root:@tcp(127.0.0.1:3306)/gardendb")
	if err != nil {
		panic(err.Error())
	}
}

/***************************************************/

// CORSRouterDecorator applies CORS headers to a mux.Router
type CORSRouterDecorator struct {
	R *mux.Router
}

func (c *CORSRouterDecorator) ServeHTTP(rw http.ResponseWriter,
	req *http.Request) {
	if origin := req.Header.Get("Origin"); origin != "" {
		rw.Header().Set("Access-Control-Allow-Origin", origin)
		rw.Header().Set("Access-Control-Allow-Methods",
			"POST, GET, OPTIONS, PUT, DELETE")
		rw.Header().Set("Access-Control-Allow-Headers",
			"Accept, Accept-Language,"+
				" Content-Type, YourOwnHeader")
	}
	// Stop here if its Preflighted OPTIONS request
	if req.Method == "OPTIONS" {
		return
	}

	c.R.ServeHTTP(rw, req)
}

type RestErr struct {
	Message string
	Status  int
	Error   string
}

func NewInternalServerError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Status:  http.StatusInternalServerError,
		Error:   "internal_server_error",
	}
}

func NewBadRequestError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Status:  http.StatusBadRequest,
		Error:   "bad_request",
	}
}