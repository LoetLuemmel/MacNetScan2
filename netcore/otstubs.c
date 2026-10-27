/* otstubs.c - what Symantec C++ 7's linker wants from Open Transport's 68K libraries and nothing calls.
   MPW's linker drops library modules no client code reaches; Symantec's keeps them, so their references must resolve
   (Apple DTS "OT + Symantec C++ Q&A", Quinn 1996, in the OT SDK's Sample Code: "Using Symantec/OT"). The AppleBridge
   daemon links these very libraries under MPW without ASLM, C++ runtime or errno, and runs - nothing an OT client calls
   reaches them; the DebugStr would say so if one ever did. Compile as C (extern "C" when a C++ file includes it). */

#ifdef __cplusplus
extern "C" {
#endif

/* prototypes first: the TCL project compiles with "Require prototypes" */
void SetSelfAsClient(void);
void LoadClass(void);
void SetCurrentClient(void);
void UnloadClass(void);
void __SLM11ExtblDispatch(void);
void __SLM11VTableDispatch(void);
void __SLM11DestructorDispatch(void);
void __SLM11ConstructorDispatch(void);

void SetSelfAsClient(void)  { DebugStr("\pSetSelfAsClient -- This is not good."); }
void LoadClass(void)        { DebugStr("\pLoadClass -- This is not good."); }
void SetCurrentClient(void) { DebugStr("\pSetCurrentClient -- This is not good."); }
void UnloadClass(void)      { DebugStr("\pUnloadClass -- This is not good."); }
/* The same reason holds for the rest: MPW's linker drops library modules no client code reaches, Symantec's keeps
   them, so their references must resolve. The AppleBridge daemon links these very OT libraries under MPW without ASLM,
   C++ runtime or errno and runs - nothing an OT client calls reaches them. */
void __SLM11ExtblDispatch(void)       { DebugStr("\p__SLM11ExtblDispatch -- This is not good."); }
void __SLM11VTableDispatch(void)      { DebugStr("\p__SLM11VTableDispatch -- This is not good."); }
void __SLM11DestructorDispatch(void)  { DebugStr("\p__SLM11DestructorDispatch -- This is not good."); }
void __SLM11ConstructorDispatch(void) { DebugStr("\p__SLM11ConstructorDispatch -- This is not good."); }
#ifdef OTSTUBS_NO_ANSI
/* only for a project without the ANSI library (OTProbe): ANSI++ in the TCL project defines both. CPlusLib (operator
   delete for the OT library) registers static destructors with atexit; a probe has none to run. */
int errno;
int atexit(void (*f)(void));
int atexit(void (*f)(void)) { return f ? 0 : 0; }
#endif

#ifdef __cplusplus
}
#endif
