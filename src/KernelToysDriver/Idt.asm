.code

; Loads the IDT pointed to by rcx 
LoadIDT PROC PUBLIC
    lidt fword ptr [rcx]
    ret
LoadIDT ENDP

; Triggers interrupt 3
IntThree PROC PUBLIC
    int 3 
    ret 
IntThree ENDP

end