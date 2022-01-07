# WebTransportServer

基于quic-go的封装，用于支持WebTransport。以下是使用Example

```go
http.HandleFunc("/counter", func(rw http.ResponseWriter, r *http.Request) {
  fmt.Printf("%v", r.Header)
})
server := NewWebTransportServer(Config{
  ListenAddr:     ":4433",
  TLSCertPath:    "quic.pem",
  TLSKeyPath:     "quic.key",
  AllowedOrigins: []string{"localhost", "::1"},
})
go func() {
  for sess := range server.Session {
    fmt.Printf("ReceiveSession:%v", sess.RemoteAddr())
    go func() {
      for {
        msg, _ := sess.ReceiveMessage()
        fmt.Printf("ReceiveMessage:% x", msg)
      }
    }()
    go func() {
      for {
        uniS, _ := sess.AcceptUniStream(sess.Context())
        buf := make([]byte, 1024)
        n, _ := uniS.Read(buf)
        fmt.Printf("receive from UniStream:% x", buf[:n])
      }
    }()
    go func() {
      for {
        s, _ := sess.AcceptStream(sess.Context())
        buf := make([]byte, 1024)
        n, _ := s.Read(buf)
        fmt.Printf("receive from Stream:% x", buf[:n])
        s.Write(buf[:n])
      }
    }()
  }
}()
if err := server.Run(); err != nil {
  log.Fatal(err)
}
```