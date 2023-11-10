import os
import sys
import hashlib
import tkinter as tkinter
from tkinter import filedialog
from Cryptodome.Cipher import ARC4

# Penjelasan sederhana tentang proses enkripsi dan dekripsi RC4
class StreamCipherRC4:
    #  KSA    
    def keyStateArray(self,key):
        S = [i for i in range(0, 256)]
        
        i = 0
        for j in range(0, 256):
            i = (i + S[j] + key[j % len(key)]) % 256
            
            tmp = S[j]
            S[j] = S[i]
            S[i] = tmp #tukar elemen
            
        return S
        
    # PRGA
    def pseudoRandomGenerationAutomation(self,S):
        i = 0
        j = 0
        while True:
            i = (1 + i) % 256
            j = (S[i] + j) % 256
            
            tmp = S[j]
            S[j] = S[i]
            S[i] = tmp #tukar elemen
            
            yield S[(S[i] + S[j]) % 256] # tambahkan elemen dan mod 256       


    def encryption(self,text, key):
        text = [ord(char) for char in text]
        key = [ord(char) for char in key]
        
        S = self.keyStateArray(key)
        keyStream = self.pseudoRandomGenerationAutomation(S)
        
        ciphertext = ''
        for char in text:
            enc = str(hex(char ^ next(keyStream))).upper()
            ciphertext += (enc)
            
        return ciphertext
        

    def decryption(self,ciphertext, key):
        ciphertext = ciphertext.split('0X')[1:]
        ciphertext = [int('0x' + c.lower(), 0) for c in ciphertext]
        key = [ord(char) for char in key]
        
        S = self.keyStateArray(key)
        keyStream = self.pseudoRandomGenerationAutomation(S)
        
        plaintext = ''
        for char in ciphertext:
            dec = str(chr(char ^ next(keyStream)))
            plaintext += dec
        
        return plaintext

#Enkripsi dan Dekripsi RC4
class EncryptionDecryptionTool:
    def __init__(self, userFile, userKey):
        # dapatkan jalur ke file masukan
        self.userFile = userFile

        self.inputFileSize = os.path.getsize(self.userFile)
        self.chunkSize = 1024
        self.totalChunks = (self.inputFileSize // self.chunkSize) + 1
        
        # mengonversi kunci menjadi byte
        self.userKey = bytes(userKey, "utf-8")
        
        # dapatkan ekstensi file
        self.fileExtension = self.userFile.split(".")[-1]
        
        # tipe hash untuk kunci hashing
        self.hashType = "SHA256"

        # nama file terenkripsi
        self.encryptOutputFile = ".".join(self.userFile.split(".")[:-1]) \
            + "." + self.fileExtension + ".rc4"

        # nama file yang didekripsi
        self.decryptOutputFile = self.userFile.split(".")
        self.decryptOutputFile = ".".join(self.decryptOutputFile[:-2]) \
            + "." + self.decryptOutputFile[1]

        # kamus untuk menyimpan kunci hash
        self.hashedKey = dict()

        # kunci hash dan menjadi hash 32 bit
        self.hashKey()

    def readInChunks(self, fileObject, chunkSize=1024):
        while True:
            data = fileObject.read(chunkSize)
            if not data:
                break
            yield data

    def encryption(self):
        # membuat objek sandi
        cipherObject = ARC4.new(
            self.hashedKey["key"]
        )

        inputFile = open(self.userFile, "rb")
        outputFile = open(self.encryptOutputFile, "ab")
        chunksDone = 0

        for piece in self.readInChunks(inputFile, self.chunkSize):
            encryptedContent = cipherObject.encrypt(piece)
            outputFile.write(encryptedContent)
            chunksDone += 1
            yield (chunksDone / self.totalChunks) * 100
        
        inputFile.close()
        outputFile.close()
        # bersihkan objek sandi

        del cipherObject

    def decryption(self):
        # membuat objek sandi
        cipherObject = ARC4.new(
            self.hashedKey["key"]
        )

        # hapus file jika file sudah ada
        self.abort()

        inputFile = open(self.userFile, "rb")
        outputFile = open(self.decryptOutputFile, "xb")
        chunksDone = 0

        for piece in self.readInChunks(inputFile):
            decryptedContent = cipherObject.decrypt(piece)
            outputFile.write(decryptedContent)
            chunksDone += 1
            yield (chunksDone / self.totalChunks) * 100
        
        inputFile.close()
        outputFile.close()

        # bersihkan objek sandi
        del cipherObject

    def abort(self):
        if os.path.isfile(self.encryptOutputFile):
            os.remove(self.encryptOutputFile)
        if os.path.isfile(self.decryptOutputFile):
            os.remove(self.decryptOutputFile)


    def hashKey(self):
        # konversi kunci menjadi hash
        # buat objek hash baru
        hasher = hashlib.new(self.hashType)
        hasher.update(self.userKey)

        # ubah hash kunci keluaran menjadi 32 byte (256 bit)
        self.hashedKey["key"] = bytes(hasher.hexdigest()[:32], "utf-8")

        # bersihkan objek hash
        del hasher

# GUI
class MainWindow:

    # konfigurasikan jalur direktori root relatif terhadap file ini
    
    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root):
        self.root = root
        self.cipher = None
        self.cipherText = ""
        self.plainText= ""
        self.cipherPlainText = tkinter.StringVar()
        self.fileUrl = tkinter.StringVar()
        self.text = tkinter.StringVar()
        self.secretKey = tkinter.StringVar()
        self.status = tkinter.StringVar()
        self.status.set("---")

        self.shouldCancel = False

        root.title("RC4 Stream Cipher Encryption Python")
        root.configure(bg="#FFFDD0")

        self.fileEntryLabel = tkinter.Label(
            root,
            text="Enter File Path Or Click SELECT FILE Button",
            bg="#FFFDD0",
            fg="#000000",
            anchor=tkinter.W
        )
        self.fileEntryLabel.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.fileEntry = tkinter.Entry(
            root,
            textvariable=self.fileUrl,
            bg="#fff",
            exportselection=0,
            relief=tkinter.FLAT
        )
        self.fileEntry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=1,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.selectBtn = tkinter.Button(
            root,
            text="SELECT FILE",
            command=self.selectFileCallback,
            width=42,
            bg="#1089ff",
            fg="#000000",
            bd=2,
            relief=tkinter.FLAT
        )
        self.selectBtn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=2,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.textEntryLabel = tkinter.Label(
            root,
            text="Enter Text",
            bg="#FFFDD0",
            fg="#000000",
            anchor=tkinter.W
        )
        self.textEntryLabel.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=3,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.textEntry = tkinter.Entry(
            root,
            textvariable=self.text,
            bg="#fff",
            exportselection=0,
            relief=tkinter.FLAT
        )
        self.textEntry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=4,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.plainCipherResultLabel = tkinter.Label(
            root,
            text="Palin/Cipher Text Result:",
            bg="#FFFDD0",
            fg="#000000",
            anchor=tkinter.W
        )
        self.plainCipherResultLabel.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=5,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.plainCipherResult = tkinter.Entry(
            root,
            bg="#fff",
            textvariable=self.cipherPlainText,
            exportselection=0,
            state='disabled',
            relief=tkinter.FLAT,
        )
        self.plainCipherResult.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=6,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.keyEntryLabel = tkinter.Label(
            root,
            text="Enter Key for Encryption and Decryption",
            bg="#FFFDD0",
            fg="#000000",
            anchor=tkinter.W
        )
        self.keyEntryLabel.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=7,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.keyEntry = tkinter.Entry(
            root,
            textvariable=self.secretKey,
            bg="#fff",
            exportselection=0,
            relief=tkinter.FLAT
        )
        self.keyEntry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=8,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.encryptBtn = tkinter.Button(
            root,
            text="ENCRYPT",
            command=self.encryptCallback,
            bg="#ed3833",
            fg="#000000",
            bd=2,
            relief=tkinter.FLAT
        )
        self.encryptBtn.grid(
            padx=(15, 6),
            pady=8,
            ipadx=24,
            ipady=6,
            row=9,
            column=0,
            columnspan=2,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )
        
        self.decryptBtn = tkinter.Button(
            root,
            text="DECRYPT",
            command=self.decryptCallback,
            bg="#00bd56",
            fg="#000000",
            bd=2,
            relief=tkinter.FLAT
        )
        self.decryptBtn.grid(
            padx=(6, 15),
            pady=8,
            ipadx=24,
            ipady=6,
            row=9,
            column=2,
            columnspan=2,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.resetBtn = tkinter.Button(
            root,
            text="RESET",
            command=self.resetCallback,
            bg="#aaaaaa",
            fg="#000000",
            bd=2,
            relief=tkinter.FLAT
        )
        self.resetBtn.grid(
            padx=15,
            pady=(4, 12),
            ipadx=24,
            ipady=6,
            row=10,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.statusBtn = tkinter.Label(
            root,
            textvariable=self.status,
            bg="#FFFDD0",
            fg="#000000",
            anchor=tkinter.W,
            justify=tkinter.LEFT,
            relief=tkinter.FLAT,
            wraplength=350
        )
        self.statusBtn.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=11,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

    def selectFileCallback(self):
        try:
            name = filedialog.askopenfile()
            self.fileUrl.set(name.name)
    
        except Exception as e:
            self.status.set(e)
            self.statusBtn.update()
    
    def freezeControls(self):
        self.fileEntry.configure(state="disabled")
        self.textEntry.configure(state="disabled")
        self.plainCipherResult.configure(state="disabled")
        self.keyEntry.configure(state="disabled")
        self.selectBtn.configure(state="disabled")
        self.encryptBtn.configure(state="disabled")
        self.decryptBtn.configure(state="disabled")
        self.resetBtn.configure(text="CANCEL", command=self.cancelCallback,
            fg="#ed3833", bg="#fafafa")
        self.statusBtn.update()
    
    def unfreezeControls(self):
        self.fileEntry.configure(state="normal")
        self.textEntry.configure(state="normal")
        self.plainCipherResult.configure(state="normal")
        self.keyEntry.configure(state="normal")
        self.selectBtn.configure(state="normal")
        self.encryptBtn.configure(state="normal")
        self.decryptBtn.configure(state="normal")
        self.resetBtn.configure(text="RESET", command=self.resetCallback,
            fg="#ffffff", bg="#aaaaaa")
        self.statusBtn.update()

    def encryptCallback(self):
        self.freezeControls()

        try:

            if not self.fileEntry.get() and self.textEntry.get():
                self.fileUrl.set("")
                streamCipherRC4 = StreamCipherRC4()
                self.cipherText = streamCipherRC4.encryption(self.textEntry.get(),self.keyEntry.get()) 
                self.status.set("Text Encrypted!")
                self.cipherPlainText.set(self.cipherText)
                if self.shouldCancel:
                    self.cipher.abort()
                    self.status.set("Cancelled!")
                self.cipher = None
                self.shouldCancel = False

            else: 
                self.cipherPlainText.set("")
                self.text.set("")   
                self.cipher = EncryptionDecryptionTool(
                    self.fileUrl.get(),
                    self.secretKey.get(),
                )
                for percentage in self.cipher.encryption():
                    if self.shouldCancel:
                        break
                    percentage = "{0:.2f}%".format(percentage)
                    self.status.set(percentage)
                    self.statusBtn.update()
                self.status.set("File Encrypted!")
                if self.shouldCancel:
                    self.cipher.abort()
                    self.status.set("Cancelled!")
                self.cipher = None
                self.shouldCancel = False
        except Exception as e:
            self.status.set(e)

        self.unfreezeControls()

    def decryptCallback(self):
        self.freezeControls()

        try:
            if not self.fileEntry.get() and self.textEntry.get():
                self.fileUrl.set("")
                streamCipherRC4 = StreamCipherRC4()
                self.plainText = streamCipherRC4.decryption(self.textEntry.get(),self.keyEntry.get()) 
                self.status.set("Text Decrypted!")
                self.cipherPlainText.set(self.plainText)
                if self.shouldCancel:
                    self.cipher.abort()
                    self.status.set("Cancelled!")
                self.cipher = None
                self.shouldCancel = False

            else:         
                self.cipherPlainText.set("")
                self.text.set("")
                self.cipher = EncryptionDecryptionTool(
                    self.fileUrl.get(),
                    self.secretKey.get(),
                )
                for percentage in self.cipher.decryption():
                    if self.shouldCancel:
                        break
                    percentage = "{0:.2f}%".format(percentage)
                    self.status.set(percentage)
                    self.statusBtn.update()
                self.status.set("File Decrypted!")
                if self.shouldCancel:
                    self.cipher.abort()
                    self.status.set("Cancelled!")
                self.cipher = None
                self.shouldCancel = False
        except Exception as e:
            self.status.set(e)
        
        self.unfreezeControls()

    def resetCallback(self):
        self.cipher = None
        self.fileUrl.set("")
        self.cipherPlainText.set("")
        self.text.set("")
        self.secretKey.set("")
        self.status.set("---")
    
    def cancelCallback(self):
        self.shouldCancel = True


if __name__ == "__main__":
    ROOT = tkinter.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()
