// authlite.go
//
// A lightweight, non-critical authorization library that stores its
// data in CSV files.
//
// https://github.com/d2718/authlite
//
// 2019-11-14
//
package authlite

import( "encoding/csv"; "errors"; "fmt"; "io/ioutil"; "log"; "math/rand";
        "os"; "strconv"; "sync"; "time";
        "golang.org/x/crypto/bcrypt";
        "github.com/d2718/dconfig";
)

const DEBUG bool = false

// This one sync.Mutex protects both files.
var file_mu *sync.Mutex
var hash_file, key_file string
// None of these four are protected by mutices because they should only ever be
// changed during the explicitly-non-thread-safe Configure().
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

// UsersDirty() returns true if changes have been made to the user data
// (users have been added or deleted) since the last time the user data
// was read from or flushed to disk.
//
func UsersDirty() bool {
    umu.RLock()
    b := udirty
    umu.RUnlock()
    return b
}

// KeysDirty() returns true if changes have been made to the key data
// (session keys have been added or culled) since the last time the key
// data was read from or flushed to disk.
//
func KeysDirty()  bool {
    kmu.RLock()
    b := kdirty
    kmu.RUnlock()
    return b
}

// ensure_exists_writably() is used by Configure() (below) to ensure that
// the files for storing password hashes and session keys exist and are
// writable. It will attempt to create them if they are not.

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

// LoadUsers() attempts to load username/password hash data from the file
// specified in the USER_FILE configuation option. If current user data
// has changed (by adding or deleting users, say) since the last time
// FlushUsers() (below) was called, those changes will be lost.
//
// When successful, LoadUsers() will flag the user data as "clean", and
// UsersDirty() (above) will return false until a change is made.
//
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

// FlushUsers() writes all user data (usernames and password hashes) to the
// file specified with the USER_FILE configuration option. On success it will
// flag the user data as "clean", and UsersDirty() (above) will return false
// until a change is made.
//
func FlushUsers() error {
    log.Printf("FlushUsers() called")
    if hash_file == "" {
        return fmt.Errorf("No USER_FILE set. Try calling Configure() first.")
    }
    
    umu.Lock()
    file_mu.Lock()
    defer file_mu.Unlock()
    defer umu.Unlock()
    
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

// LoadKeys() attempts to load data about temporary session keys from the
// file specified with the KEY_FILE configuration option. It will ignore
// expired keys. On success it will flag the key data as "clean", and
// KeysDirty() will return false until a new key is issued or old keys
// are culled.
//
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

// FlushKeys() writes session key data to the file specified in the KEY_FILE
// configuration option. Ignores expired keys (they will not be written).
// On success it will flag the key data as "clean", and KeysDirty() will
// return false until a new key is issued or old keys are culled.
//
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
    kmu.Lock()
    defer kmu.Unlock()
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

// Configure(cfg_path string) reads the configuration file at cfg_path, sets
// options appropriately, and initializes everything that needs to be
// initialized. It also calls LoadUsers() and LoadKeys() to load all data.
//
// Configure() IS NOT thread-safe. It should just be called once at the
// beginning of your program, before any authorization needs to take place.
// If you need to reconfigure this module mid-program, you can either try
// introducing a careful locking dance, or ensuring all your auth-requiring
// threads are stopped. I don't know which will be more painful.
//
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
    err := dconfig.Configure([]string{cfg_path}, true)
    if err != nil {
        log.Printf("dconfig.Configure(...) returned error: %s", err.Error())
        return err
    }
    
    if hash_file == "" {
        return fmt.Errorf("You must configure a USER_FILE.")
    } else if key_file == "" {
        return fmt.Errorf("You must configure a KEY_FILE.")
    }
    
    err = ensure_exists_writably(hash_file)
    if err != nil {
        return fmt.Errorf("error with user file: %s", err.Error())
    }
    err = ensure_exists_writably(key_file)
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

// AddUser() adds a user with the supplied user name and password. Will
// return ErrUserExists if the supplied user name already exists. Sets the
// user data to "dirty" on success.
//
func AddUser(uname, pwd string) error {
    umu.Lock()
    defer umu.Unlock()
    if _, exists := users[uname]; exists {
        return ErrUserExists
    }
    
    pwd_hsh, err := bcrypt.GenerateFromPassword([]byte(pwd), hash_cost)
    if err != nil {
        return fmt.Errorf("Unable to hash password: %s", err.Error())
    }
    
    users[uname] = pwd_hsh
    udirty = true
    
    return nil
}
// DeleteUser() removes the user with the supplied user name. Will return
// ErrNotAUser if there is no user with the supplied user name. Sets the
// user data to "dirty" on success.
//
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

// CheckPassword() returns whether the supplied username/password combo
// checks out. Will return ErrNotAUser or ErrBadPassword as appropriate.
//
func CheckPassword(uname, pwd string) (bool, error) {
    umu.RLock()
    hsh, exists := users[uname]
    umu.RUnlock()
    if !exists {
        return false, ErrNotAUser
    }
    err := bcrypt.CompareHashAndPassword(hsh, []byte(pwd))
    if err == nil {
        return true, nil
    } else {
        log.Printf("bcrypt.CompareHashAndPassword(...) returned error: %s", err.Error())
        return false, ErrBadPassword
    }
}

// CheckKey() Checks to see whether the supplied key has been issued to
// the supplied username and has not expired. Returns ErrBadKey on failure.
//
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

// CheckPasswordAndIssueKey() checks whether the username/password combo
// checks out. If so, it will generate (and return) a new key associated with
// that username. Returns an empty string and appropriate error if the
// username/password combo is bad.
//
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

// CheckAndRefreshKey() checks whether the supplied key has been issued to
// the supplied username and has not expired; returns appropriate error
// if not. If the username/key combo is good, the key's expiry time will
// be reset (to now + key_lifetime), and key data will be set to "dirty".
//
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

// CullOldKeys() grovels through issued keys and removes expired ones. If it
// removes anything, it sets key data to "dirty".
//
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
    if len(old) > 0 { kdirty = true }
    kmu.Unlock()
    return
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
