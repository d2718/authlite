// authlite.go
//
// A lightweight, non-critical authorization library that stores its
// data in CSV files.
//
// https://github.com/d2718/authlite
//
// 2019-11-12
//
package authlite

import( "encoding/csv"; "errors"; "fmt"; "io/ioutil"; "log"; "math/rand";
        "os"; "strconv"; "sync"; "time";
        "golang.org/x/crypto/bcrypt";
        "github.com/d2718/dconfig";
)

const DEBUG bool = true

var file_mu *sync.Mutex
var hash_file, key_file string
var key_length   int = 32
var key_runes []rune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
var hash_cost    int = 5
var key_lifetime time.Duration

type key struct {
    uname string
    until time.Time
}

var umu    *sync.RWMutex
var users  map[string][]byte
var udirty bool
var kmu    *sync.RWMutex
var keys   map[string]key
var kdirty bool

var(
    ErrUserExists  = fmt.Errorf("a user with that username already exists")
    ErrNotAUser    = fmt.Errorf("a user with that username doesn't exist")
    ErrBadPassword = fmt.Errorf("bad username/password combination")
    ErrBadKey      = fmt.Errorf("nonexistent or expired key")
)

func UsersDirty() bool { return udirty }
func KeysDirty()  bool { return kdirty }

func ensure_exists_writably(path string) error {
    fi, err := os.Stat(path)
    if errors.Is(err, os.ErrNotExist) {
        log.Printf("File %q does not exist; creating.", path)
        f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
        if err != nil {
            return fmt.Errorf("error creating file %q: %s", path, err.Error())
        }
        err = f.Close()
        if err != nil {
            return fmt.Errorf("error closing file %q: %s", path, err.Error())
        }
        return nil
    } else if err != nil {
        return fmt.Errorf("unable to stat %q: %s", path, err.Error())
    }
    
    if (fi.Mode().Perm() & 0600) != 0600 {
        return fmt.Errorf("%q is not read/writeable", path)
    }
    return nil
}

// hash_file format:
//
// uname,hashed_pwd_as_string

func LoadUsers() error {
    log.Printf("LoadUsers() called")
    if hash_file == "" {
        return fmt.Errorf("No USER_FILE set. Try calling Configure() first.")
    }
    
    file_mu.Lock()
    f, err := os.Open(hash_file)
    if err != nil {
        file_mu.Unlock()
        return fmt.Errorf("Unable to open user file %q for reading: %s", hash_file, err.Error())
    }
    
    r := csv.NewReader(f)
    
    recs, err := r.ReadAll()
    if err != nil {
        f.Close()
        file_mu.Unlock()
        return fmt.Errorf("Error reading from user file %q: %s", hash_file, err.Error())
    }
    err = f.Close()
    file_mu.Unlock()
    if err != nil {
        return fmt.Errorf("Error closing user file %q: %s", hash_file, err.Error())
    }
    
    umu.Lock()
    defer umu.Unlock()
    users = make(map[string][]byte)
    for _, r := range recs {
        if len(r) < 2 {
            return fmt.Errorf("User file %q has unreadable format.", hash_file)
        }
        users[r[0]] = []byte(r[1])
    }
    log.Printf("Loaded %d users.", len(users))
    udirty = false
    
    return nil
}

func FlushUsers() error {
    log.Printf("FlushUsers() called")
    if hash_file == "" {
        return fmt.Errorf("No USER_FILE set. Try calling Configure() first.")
    }
    
    umu.RLock()
    file_mu.Lock()
    defer file_mu.Unlock()
    defer umu.RUnlock()
    
    f, err := os.OpenFile(hash_file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 644)
    if err != nil {
        return fmt.Errorf("Error opening user file %q for writing: %s", hash_file, err.Error())
    }
    
    w := csv.NewWriter(f)
    var n_written int = 0
    for uname, phash := range users {
        err = w.Write([]string{ uname, string(phash) })
        if err != nil {
            f.Close()
            return fmt.Errorf("Error writing to user file %q: %s", hash_file, err.Error())
        }
        n_written++
    }
    
    w.Flush()
    err = w.Error()
    if err != nil {
        f.Close()
        return fmt.Errorf("Error flushing user file %q to disk: %s", hash_file, err.Error())
    }
    
    err = f.Close()
    if err != nil {
        return fmt.Errorf("Error closing user file %q: %s", hash_file, err.Error())
    }
    
    log.Printf("Wrote %d users.", n_written)
    udirty = false
    return nil
}

// key file format:
//
// uname,exptime,key

func LoadKeys() error {
    log.Printf("LoadKeys() called")
    if key_file == "" {
        return fmt.Errorf("No KEY_FILE set. Try calling Configure() first.")
    }
    
    file_mu.Lock()
    f, err := os.Open(key_file)
    if err != nil {
        file_mu.Unlock()
        return fmt.Errorf("Error opening key file %q for read: %s", key_file, err.Error())
    }
    
    r := csv.NewReader(f)
    recs, err := r.ReadAll()
    if err != nil {
        f.Close()
        file_mu.Unlock()
        return fmt.Errorf("Error reading key file %q: %s", key_file, err.Error())
    }
    err = f.Close()
    file_mu.Unlock()
    if err != nil {
        return fmt.Errorf("Error closing key file %q: %s", key_file, err.Error())
    }
    
    now := time.Now()
    kmu.Lock()
    defer kmu.Unlock()
    keys = make(map[string]key)
    for _, r := range recs {
        if len(r) < 3 {
            return fmt.Errorf("Key file %q has unreadable format.", key_file)
        }
        t_num, _ := strconv.ParseUint(r[1], 10, 64)
        t := time.Unix(int64(t_num), 0)
        if now.Before(t) {
            keys[r[2]] = key{ uname: r[0], until: t }
        }
    }
    log.Printf("Loaded %d keys.", len(keys))
    kdirty = false
    return nil
}

func FlushKeys() error {
    log.Printf("FlushKeys() called")
    if key_file == "" {
        return fmt.Errorf("No KEY_FILE set. Try calling Configure() first.")
    }
    
    file_mu.Lock()
    f, err := os.OpenFile(key_file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 644)
    defer file_mu.Unlock()
    if err != nil {
        return fmt.Errorf("Error opening key file %q for writing: %s", key_file, err.Error())
    }
    
    w := csv.NewWriter(f)
    
    now := time.Now()
    var n_written int = 0
    kmu.RLock()
    defer kmu.RUnlock()
    for k, v := range keys {
        if v.until.After(now) {
            err = w.Write([]string{ v.uname, fmt.Sprintf("%d", v.until.Unix()), k })
            if err != nil {
                f.Close()
                return fmt.Errorf("Error writing to key file %q: %s", key_file, err.Error())
            }
            n_written++
        }
    }
    w.Flush()
    err = f.Close()
    if err != nil {
        return fmt.Errorf("Error closing key file %q: %s", key_file, err.Error())
    }
    log.Printf("Wrote %d keys.", n_written)
    kdirty = false
    return nil
}

func Configure(cfg_path string) error {
    log.Printf("Configure(%q) called", cfg_path)
    
    var key_char_str string = string(key_runes)
    var key_life_cfg_int int = 600
    dconfig.Reset()
    dconfig.AddString(&hash_file,     "user_file",    dconfig.STRIP)
    dconfig.AddString(&key_file,      "key_file",     dconfig.STRIP)
    dconfig.AddInt(&key_length,       "key_length",   dconfig.UNSIGNED)
    dconfig.AddString(&key_char_str,  "key_chars",    dconfig.STRIP)
    dconfig.AddInt(&hash_cost,        "hash_cost",    dconfig.UNSIGNED)
    dconfig.AddInt(&key_life_cfg_int, "key_lifetime", dconfig.UNSIGNED)
    file_mu.Lock()
    err := dconfig.Configure([]string{cfg_path}, true)
    file_mu.Unlock()
    if err != nil {
        log.Printf("dconfig.Configure(...) returned error: %s", err.Error())
        return err
    }
    
    if hash_file == "" {
        return fmt.Errorf("You must configure a USER_FILE.")
    } else if key_file == "" {
        return fmt.Errorf("You must configure a KEY_FILE.")
    }
    
    file_mu.Lock()
    err = ensure_exists_writably(hash_file)
    if err != nil {
        file_mu.Unlock()
        return fmt.Errorf("error with user file: %s", err.Error())
    }
    err = ensure_exists_writably(key_file)
    file_mu.Unlock()
    if err != nil {
        return fmt.Errorf("error with key file: %s", err.Error())
    }
    
    key_runes = []rune(key_char_str)
    key_lifetime = time.Duration(time.Duration(key_life_cfg_int) * time.Second)
    
    err = LoadUsers()
    if err != nil {
        return fmt.Errorf("Error loading users: %s", err.Error())
    }
    err = LoadKeys()
    if err != nil {
        return fmt.Errorf("Error loading keys: %s", err.Error())
    }
    
    return nil
}

func generate_key() string {
    max_n := len(key_runes)
    k := make([]rune, key_length)
    for n := 0; n < key_length; n++ {
        k[n] = key_runes[rand.Intn(max_n)]
    }
    return string(k)
}

func AddUser(uname, pwd string) error {
    umu.RLock()
    if _, exists := users[uname]; exists {
        return ErrUserExists
    }
    umu.RUnlock()
    
    pwd_hsh, err := bcrypt.GenerateFromPassword([]byte(pwd), hash_cost)
    if err != nil {
        return fmt.Errorf("Unable to hash password: %s", err.Error())
    }
    
    umu.Lock()
    users[uname] = pwd_hsh
    udirty = true
    umu.Unlock()
    
    return nil
}

func DeleteUser(uname string) error {
    umu.Lock()
    defer umu.Unlock()
    if _, exists := users[uname]; exists {
        delete(users, uname)
        udirty = true
        return nil
    } else {
        return ErrNotAUser
    }
}

func CheckPassword(uname, pwd string) (bool, error) {
    umu.RLock()
    hsh, exists := users[uname]
    umu.RUnlock()
    if !exists {
        return false, ErrNotAUser
    }
    err := bcrypt.CompareHashAndPassword(hsh, []byte(pwd))
    //
    // TODO: Possibly alter this to give more information via the error
    //
    if err == nil {
        return true, nil
    } else {
        log.Printf("bcrypt.CompareHashAndPassword(...) returned error: %s", err.Error())
        return false, ErrBadPassword
    }
}

func CheckKey(uname, keystr string) (bool, error) {
    kmu.RLock()
    k, exists := keys[keystr]
    kmu.RUnlock()
    if exists {
        if uname == k.uname {
            if k.until.After(time.Now()) {
                return true, nil
            }
        }
    }
    return false, ErrBadKey
}

func CheckPasswordAndIssueKey(uname, pwd string) (string, error) {
    ok, err := CheckPassword(uname, pwd)
    if !ok {
        return "", err
    }
    kstr := generate_key()
    kmu.Lock()
    keys[kstr] = key{ uname: uname, until: time.Now().Add(key_lifetime) }
    kdirty = true
    kmu.Unlock()
    return kstr, nil
}

func CheckAndRefreshKey(uname, keystr string) (bool, error) {
    ok, err := CheckKey(uname, keystr)
    if !ok { return false, err}
    kmu.Lock()
    k := keys[keystr]
    k.until = time.Now().Add(key_lifetime)
    keys[keystr] = k
    kdirty = true
    kmu.Unlock()
    return true, nil
}

func CullOldKeys() {
    old := make([]string, 0, 0)
    now := time.Now()
    kmu.RLock()
    for kstr, kval := range keys {
        if now.After(kval.until) {
            old = append(old, kstr)
        }
    }
    kmu.RUnlock()
    kmu.Lock()
    for _, kstr := range old {
        delete(keys, kstr)
    }
    kmu.Unlock()
}

func init() {
    if DEBUG {
        log.SetOutput(os.Stderr)
        log.SetFlags( log.Ldate | log.Ltime | log.Lshortfile)
    } else {
        log.SetOutput(ioutil.Discard)
    }
    
    file_mu = new(sync.Mutex)
    umu = new(sync.RWMutex)
    kmu = new(sync.RWMutex)
    
    rand.Seed(time.Now().UnixNano())
}