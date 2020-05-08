(define-module (gnu packages uutunnel)
  #:use-module (guix)
  #:use-module (guix build-system gnu)
  #:use-module (guix licenses)
  #:use-module (gnu packages musl)
  #:use-module (gnu packages compression))

(define-public uutunnel
  (package
    (name "uutunnel")
    (version "0.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/rixed/" name "/archive/v"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1bwbh6644mlp5dykvig3k7hf85qrk1kc81r7vq71ibrx91l8cr62"))))
    (build-system gnu-build-system)
    (arguments
      '(#:phases
        (modify-phases %standard-phases
                       (delete 'configure)
                       (replace 'install
                                (lambda* (#:key inputs outputs #:allow-other-keys)
                                         (let* ((out (assoc-ref outputs "out"))
                                                (bin (string-append out "/bin")))
                                           (install-file "uutunnel" bin)
                                           #t))))
        #:tests? #f  ; uses `cc`
        #:strip-binaries? #f  ; handled internally
        #:make-flags
        (list "NOMUSL=1" "NDEBUG=1" "CC=gcc")))
    (native-inputs `(("musl" ,musl)
                     ("upx" ,upx)))
    (synopsis "Port forwarding like it's 1980")
    (description
      (string-append
        "A tool to forward ports through the terminal - "
        "comes handy with remote containers!"))
    (home-page "https://github.com/rixed/uutunnel")
    (license gpl3+)))
