// authlite_test.go
//
// Testing for the authlite package.
//
// 2019-11-13
//
package authlite

import( "os"; "testing" )

var test_users = map[string]string{
    "larry":    "larryxrulz",
    "moe":      "andyhair",
    "curly":    "Mr. Dan H41r",
}

var tv = map[string]interface{} {
    "hash_file" : "test_users.csv",
    "key_file"  : "test_keys.csv",
    "key_length": 26,
    "key_runes" : "asdfjkl;2357",
    "hash_cost" : 5,
    "key_life"  : 120,
}

func errpt(tvkey string, val interface{}, t *testing.T) {
    t.Errorf("%q: expected %v, got %v", tvkey, tv[tvkey], val)
}

func TestConfigure(t *testing.T) {
    err := Configure("test.conf")
    if err != nil {
        t.Errorf("Configure() returned error: %s", err.Error())
    }
    
    if hash_file    != "test_users.csv" { errpt("hash_file", hash_file, t) }
    if key_file     != "test_keys.csv"  { errpt("key_file", key_file, t) }
    if key_length   != 26               { errpt("key_length", key_length, t) }
    tkcharz := string(key_runes)
    if tkcharz      != "asdfjkl;2357"   { errpt("key_runes", tkcharz, t) }
    if hash_cost    != 5                { errpt("hash_cost", hash_cost, t) }
    if key_lifetime.Seconds() != 120.0  { errpt("key_life", key_lifetime, t) }
}

func TestAdd(t *testing.T) {
    for uname, pwd := range test_users {
        err := AddUser(uname, pwd)
        if err != nil {
            t.Errorf("AddUser(%q, %q) returned error: %s", uname, pwd, err.Error())
        }
    }
    
    err := FlushUsers()
    if err != nil {
        t.Errorf("FlushUsers() returned error: %s", err.Error())
    }
    err = LoadUsers()
    if err != nil {
        t.Errorf("LoadUsers() returned error: %s", err.Error())
    }
    umu.RLock()
    if len(test_users) != len(users) {
        t.Errorf("Post-load expected %d users, have %d.", len(test_users), len(users))
    }
    umu.RUnlock()
    
    for uname, pwd := range test_users {
        _, err := CheckPassword(uname, pwd)
        if err != nil {
            t.Errorf("CheckPasssword(%q, %q) returned error: %s", uname, pwd, err.Error())
        }
    }
}

func TestKeys(t *testing.T) {
    tkeyz := make(map[string]string)
    
    for uname, pwd := range test_users {
        nkey, err := CheckPasswordAndIssueKey(uname, pwd)
        if err != nil {
            t.Errorf("CheckPasswordAndIssueKey(%q, %q) returned error: %s", uname, pwd, err.Error())
        } else {
            tkeyz[uname] = nkey
        }
    }
    
    err := FlushKeys()
    if err != nil {
        t.Errorf("FlushKeys() returned error: %s", err.Error())
    }
    err = LoadKeys()
    if err != nil {
        t.Errorf("LoadKeys() returned error: %s", err.Error())
    }
    kmu.RLock()
    if len(test_users) != len(keys) {
        t.Errorf("Post-load expected %d keys, have %d.", len(test_users), len(keys))
    }
    kmu.RUnlock()
    
    for uname, tkey := range tkeyz {
        _, err := CheckAndRefreshKey(uname, tkey)
        if err != nil {
            t.Errorf("CheckAndRefreshKey(%q, %q) returned error: %s", uname, tkey, err.Error())
        }
    }
}

func TestCleanup(t *testing.T) {
    err := os.Remove("test_users.csv")
    if err != nil { t.Errorf("Error removing test users file.") }
    err = os.Remove("test_keys.csv")
    if err != nil { t.Errorf("Error removing test keys file.") }
}