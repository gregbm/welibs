package welibs

import ("fmt"
    "crypto/aes"
    "crypto/cipher"
            
    "crypto/rand"
           
    "encoding/base64"
    "io"
  
    "runtime"
    "os"
    "os/exec"
    "io/ioutil"
    "net/http"
    "time"
    "log"
    "syscall"
    "github.com/denisbrodbeck/machineid"
)


func Encrypt(key []byte, text string) string {
	// key := []byte(keyText)
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}
func Decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}
func Writetoenv(keyname string, keyvalue string){
    if runtime.GOOS == "windows" {
         exec.Command("powershell","setx /m",keyname+" "+keyvalue).Output()
    }   
}

func Readfromenv(key []byte, keyname string) string{
 
    KeyID := os.Getenv(keyname)
    return KeyID
    
}
func GetSystem() string{
	dll := syscall.MustLoadDLL("kernel32.dll")
	p := dll.MustFindProc("GetVersion")
	v, _, _ := p.Call()
	systemL:=fmt.Sprintf("Windows version %d.%d (Build %d)", byte(v), uint8(v>>8), uint16(v>>16))
	return (systemL)
}
func ValidateId(){
	
	id, err := machineid.ID()
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Println(id)

	url := "https://we-bit.de/test.php?thissid=" + id
	//fmt.Printf("HTML code of %s ...\n", url)
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, errx := ioutil.ReadAll(resp.Body)
	if errx != nil {
		panic(errx)
	}
	// show the HTML code as a string %s
	//fmt.Printf("%s\n", html)
	if string(html) == "Vmcf" {
		fmt.Println("Validated")
} else {
		fmt.Println("Ihr System besitzt keine gültige Lizenzierung!")
		fmt.Println("Bitte wenden Sie sich an info@we-bit.de oder")
		fmt.Println("melden Sie sich telefonisch unter 04191 / 994 90 10.")
		fmt.Println("Bitte notieren Sie sich nachfolgende ID:")
		fmt.Println(id)
		time.Sleep(60 * time.Second)
		os.Exit(0)
	}
}
// CopyFile source, destination
func CopyFile(source string, destination string){
	input, err := ioutil.ReadFile(source)
        if err != nil {
                fmt.Println(err)
                return
        }

        err = ioutil.WriteFile(destination, input, 0644)
        if err != nil {
                fmt.Println("Error creating", destination)
                fmt.Println(err)
                return
        }
}
// FormatTimeLine Fileextension without dot as string
func FormatTimeLine(extension string) string {
	currentTime := time.Now()
	fmt.Println("Current Time in String: ", currentTime.String())
	extension = "." + extension
	TimeString := fmt.Sprintf(currentTime.Format("02-01-2006 15-04-05 Monday%v"), extension)
	return TimeString
}
// EncryptFile key, source, destination
func EncryptFile(key []byte, source string, destination string){
	fileName := source
	file, err := os.Open(fileName)
	if err != nil {
		//
	}
	defer file.Close()

	b, err := ioutil.ReadFile(fileName) // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	encrypted := Encrypt(key, string(b))

	f, _ := os.Create(destination)

	file, err = os.OpenFile(destination, os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
	}
	
	file.WriteString(string(encrypted))

	
	f.Close()
}
// DecryptFile key, source, destination
func DecryptFile(key []byte, source string, destination string){
	fmt.Println(string(key))
	fileName := source
	file, err := os.Open(fileName)
	
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	
	b, err := ioutil.ReadFile(fileName) // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	
	decrypted := Decrypt(key, string(b))
	
	f, _ := os.Create(destination)

	file, err = os.OpenFile(destination, os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
	}

	file.WriteString(string(decrypted))
	//fmt.Println(decrypted)
	f.Close()
}
