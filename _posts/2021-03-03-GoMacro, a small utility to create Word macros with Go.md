---
title:  "GoMacro: a small utility to create Word macros with Go"
layout: post
---

Small utility and lib to create Word Documents with malicious macros.


I was browsing around on Github and found a really nice project by [@EmericNasi](https://twitter.com/emericnasi). It's called [macro_pack](https://github.com/sevagas/macro_pack). The project uses `win32com` python library to manage different Office documents and inject macro inside them.   
Back when I found out about this project, I was learning Go while also reading **Black Hat Go** by Tom Steele, Chris Patten, and Dan Kottmann. So, naturally, I wanted to reproduce some capabilities of `macro_pack`, but in pure Go. Because... why not?   

The Python library `win32com`, uses a subset of **Component Object Model** (COM) called **Object Linking and Embedding** (OLE) to communicate with Office (Word, Excel, etc). I won't go into details because my understanding stops here, so I short, you need a client that talks OLE to be able to send commands to Office Word. This is exactly what [go-ole](https://github.com/go-ole/go-ole) does. Except that, the library is too much low level to be easily usable, that is why I started writing `gomacro`.

## GoMacro

The repository can be found on github -> [https://github.com/oXis/gomacro](https://github.com/oXis/gomacro)

It is organised in multiple parts

- `pkg/gomacro` contains the lib code that interface with go-ole.
- `pkg/obf` contains code to obfuscate VB code.
- `cmd/main` contains a complete example on how to use gomacro lib to create a Word Doc with a macro.
- `resources` contains macro VB code

## GoMacro internals
In this section we are going to talk about the `gomacro` package. This package is a wrapper to `go-ole` that facilitates Word documents manipulation.

I wanted the syntax to be close to what `win32com` proposes.

The code below shows how to create a new document and access its `VBComponent` field.

```go
// Initialise the lib
gomacro.Init()
defer gomacro.Uninitialize()

// Open Word and get a hendle to documents
documents := gomacro.NewDocuments(false)
defer documents.Close()

fmt.Printf("Word version is %s\n", documents.Application.Version)

// Add a new document
document := documents.AddDocument()

// Set the name of the new doc
document.VBProject.SetName(obf.RandWord())

// Get a handle "ThisDocument" VBA project
thisDoc, err := document.VBProject.VBComponents.GetVBComponent("ThisDocument")
if err != nil {
    fmt.Printf("%s", err)
    document.Save()
    documents.Close()
}
```

`go-ole` needs to be initialised with `ole.CoInitialize(0)`, `gomacro.Init()` is just a wrapper to that call.

`gomacro.NewDocuments(false)` creates a new document. The implementation is as follow.
```go
// NewDocument Create a new Word document
func (d *Documents) NewDocument(v bool) *Documents {

    // Create a Word.Application object 
    unknown, err := oleutil.CreateObject("Word.Application")
	if err != nil {
        panic("Cannot create Word.Application")
	}

    // Get a handle to Word.Application
	word, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		panic("Cannot QueryInterface of Word")
	}

    // Population the Application field of struct Documents
	d.Application = &Application{_Application: word,
		Options: &Options{_Options: oleutil.MustGetProperty(word, "Options").ToIDispatch()}}

    // Set visibility to v bool
	oleutil.PutProperty(d.Application._Application, "Visible", v)

    // Get a handle to the Documents from the application
	d._Documents = oleutil.MustGetProperty(d.Application._Application, "Documents").ToIDispatch()
	d.Application.Version = oleutil.MustGetProperty(d.Application._Application, "Version").ToString()

    // Permit OLE to manage VBA code inside documents
	setupRegistry(d.Application.Version, 1)

	return d
}
```

Structure that represents an `Application`

```go
//Application Holds the OLE app
type Application struct {
	_Application *ole.IDispatch // Handle to the application
	Options      *Options       // Handle to the application options
	Version      string         // Version
}
```

`Documents` and `Document` structures. `Documents` contains a `Document` and also contains an `Application`. A `Document` contains a `VBProject`.
```go 
// Documents represents Word documents
type Documents struct {
	_Documents  *ole.IDispatch
	Application *Application

	Document *Document
}

// Document represents a Word document
type Document struct {
	_Document   *ole.IDispatch
	Application *Application
	VBProject   *VBProject
}
```

A `VBProject` contains a `VBComponents`.

```go
// VBProject Holds VB projects
type VBProject struct {
	_VBProject   *ole.IDispatch
	Name         string
	VBComponents VBComponents
}
```

A `VBComponents` contains many `Components` and `Forms`. A `Components` contains a `CodeModule`.

```go
// VBComponents Holds VB conponents
type VBComponents struct {
	_VBComponents *ole.IDispatch
	Components    map[string]*VBComponent
	Forms         map[string]*Form
}

// VBComponent Holds VB conponent
type VBComponent struct {
	_VBComponent *ole.IDispatch
	CodeModule   *CodeModule
}

```

I know it's confusing, but this structure follows Microsoft's definition (I think...). From there, it is only a matter of implementing all functions. For example, `AddVBComponent` is used to add a new component (module) to a VB project.

```go
// AddVBComponent Add a new Module
func (v *VBComponents) AddVBComponent(name string, cType int) *VBComponent {
    // Call the Add function on the handle to _VBComponents OLE object, inside VBComponents. 
	comp := oleutil.MustCallMethod(v._VBComponents, "Add", cType).ToIDispatch()

	// Set its name
    comp.PutProperty("Name", name)

    // Add the new module to the list of modules inside Components and retrieve the codeModule.
	v.Components[name] = &VBComponent{_VBComponent: comp,
		CodeModule: &CodeModule{_CodeModule: oleutil.MustGetProperty(comp, "codeModule").ToIDispatch()}}

	return v.Components[name]
}
```

VB code can be added to a code module by calling `AddFromString` on the handle to the OLE object.

```go
//AddFromString Add content to the code module
func (c *CodeModule) AddFromString(content string) {
	oleutil.MustCallMethod(c._CodeModule, "AddFromString", content).ToIDispatch()
}
```

The gomacro library is not complete, but adding new functions should be very easy, the hard part is to found if should `MustCallMethod` or `MustGetProperty` to set options. And also find the correct parameters and function name.

## VB Obfuscation

The obfuscation is handle by this function. What the function is doing it getting all `functions`, `function parameters`, `variables` and `strings` from a VB code. Them, a map is create for each item that link the previous name to the new random name.

```go
// ObfuscateVBCode ...
func ObfuscateVBCode(code string, objFunc, objParam, objVar, objString bool) (string, map[string]string, map[string]string, map[string]string, map[string]string) {

	funcMap := make(map[string]string)
	if objFunc {
		functions := removeDuplicatesFromSlice(getFunctions(code))
		for _, s := range functions {
			funcMap[s] = RandWord()
		}
	}

	paramMap := make(map[string]string)
	if objParam {
		parameters := removeDuplicatesFromSlice(getFunctionsParameters(code))
		for _, p := range parameters {
			paramMap[p] = RandWord()
		}
	}

	varMap := make(map[string]string)
	if objVar {
		variables := removeDuplicatesFromSlice(getVariables(code))
		for _, p := range variables {
			varMap[p] = RandWord()
		}
	}

	stringMap := make(map[string]string)
	if objString {
		str := removeDuplicatesFromSlice(getStrings(code))
		for _, p := range str {
			formatString, formatStringList := shuffleString(p)
			stringMap[p] = fmt.Sprintf(`Format("%v", %v)`, formatString, formatStringList)
		}
	}

	return code, funcMap, paramMap, varMap, stringMap
}
```

The next step is to call the function bellow will all the maps generated by `ObfuscateVBCode`.
```go
func ReplaceAllInCode(code string, funcMap, paramMap, varMap, stringMap map[string]string) string
```

## Main

The main function is heavily commented and is rather easy to follow.

When calling `-EncodedCommand`, Powershell requires a `UTF16-LE` base64 encoded string. The function bellow, takes any Go string, encode the string to `UTF16`, add `NULL` bytes between each characters to confuse AVs, and finally `base64` encode the resulting string. The result is compatible with `-EncodedCommand` option.
```go
// newEncodedPSScript returns a UTF16-LE, base64 encoded script.
// The -EncodedCommand parameter expects this encoding for any base64 script we send over.
func newEncodedPSScript(script string) (string, error) {
	uni := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	encoded, err := uni.NewEncoder().String(script)
	if err != nil {
		return "", err
	}

	var encodedNull []byte = make([]byte, len(encoded)*2)
	for _, c := range encoded {
		encodedNull = append(encodedNull, byte(c), 0x00)
	}

	return base64.StdEncoding.EncodeToString([]byte(encoded)), nil
}
```

When calling the compiled Go binary, a new doc is generated and placed into the current directory. Windows Defender forbids executing powershell from a Word Macro, so real-time protection should be disabled. This can be bypassed but I let you find a way. This post is about making Word macros with Go, not weaponising those macros.