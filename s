void dispatch()
{
  char *v0; // r0
  const char *v1; // r6
  size_t v2; // r4
  char *v3; // r5
  size_t v4; // r0
  char *v5; // r4
  size_t v6; // r0
  char *v7; // r8
  char *v8; // r5
  const char *v9; // r5
  const char *v10; // r0
  const char *v11; // r4
  int v12; // r6
  int v13; // r7
  int v14; // r4
  regmatch_t *v15; // r8
  size_t v16; // r0
  size_t v17; // r0
  size_t v18; // r0
  size_t v19; // r0
  size_t v20; // r0
  size_t v21; // r0
  size_t v22; // r0
  size_t v23; // r0
  size_t v24; // r0
  size_t v25; // r0
  size_t v26; // r0
  size_t v27; // r0
  char v28[21]; // [sp+Fh] [bp-15h] BYREF

  v0 = getenv("HTTP_AUTHORIZATION");
  v1 = v0;
  if ( v0 )
  {
    v2 = strlen(v0);
    memset((void *)(8 * ((unsigned int)v28 >> 3)), 0, v2);
    strncpy((char *)(8 * ((unsigned int)v28 >> 3)), v1, v2);
    *(_BYTE *)(v2 + 8 * ((unsigned int)v28 >> 3)) = 0;
    strtok((char *)(8 * ((unsigned int)v28 >> 3)), " ");
    v3 = strtok(0, " ");
    v4 = strlen(v3);
    v5 = (char *)malloc(v4);
    if ( !v5 )
    {
LABEL_48:
      error_handler("Error in allocating memory");
      return;
    }
    v6 = strlen(v3);
    cyoBase64Decode(v5, v3, v6);
    v7 = strtok(v5, ":");
    v8 = strtok(0, ":");
    setenv("HTTP_USERNAME", v7, 1);
    setenv("HTTP_PASSWORD", v8, 1);
    free(v5);
  }
  v9 = (const char *)j_get_path_info();
  if ( !v9 )
  {
    error_handler("NULL path_info");
    return;
  }
  v10 = (const char *)j_get_method();
  v11 = v10;
  if ( v10 )
  {
    v12 = *(unsigned __int8 *)v10;
    if ( v12 == 71 && v10[1] == 69 && v10[2] == 84 && !v10[3] )
    {
      v13 = 1;
    }
    else if ( !strcmp(v10, "POST") )
    {
      v13 = 2;
    }
    else if ( v12 == 80 && v11[1] == 85 && v11[2] == 84 && !v11[3] )
    {
      v13 = 3;
    }
    else if ( !strcmp(v11, "HEAD") )
    {
      v13 = 4;
    }
    else if ( !strcmp(v11, "DELETE") )
    {
      v13 = 5;
    }
    else
    {
      if ( strcmp(v11, "PATCH") )
      {
        error_handler("unknown request method");
        return;
      }
      v13 = 6;
    }
    v14 = head;
    if ( !head )
    {
LABEL_32:
      error_handler("no match");
      return;
    }
    while ( 1 )
    {
      while ( *(_DWORD *)(v14 + 4) != v13 )
      {
        v14 = *(_DWORD *)(v14 + 48);
        if ( !v14 )
          goto LABEL_32;
      }
      v15 = (regmatch_t *)malloc(8 * *(_DWORD *)(v14 + 44));
      if ( !v15 )
        goto LABEL_48;
      v16 = strlen(v9);
      if ( (int)(v16 + 2) > 512 )
        goto LABEL_46;
      v17 = v16 - 1;
      if ( v9[v17] == 47 )
      {
        v9[v17] = 0;
        v18 = strlen(v9) - 1;
        if ( v9[v18] == 47 )
        {
          v9[v18] = 0;
          v19 = strlen(v9) - 1;
          if ( v9[v19] == 47 )
          {
            v9[v19] = 0;
            v20 = strlen(v9) - 1;
            if ( v9[v20] == 47 )
            {
              v9[v20] = 0;
              v21 = strlen(v9) - 1;
              if ( v9[v21] == 47 )
              {
                v9[v21] = 0;
                v22 = strlen(v9) - 1;
                if ( v9[v22] == 47 )
                {
                  v9[v22] = 0;
                  v23 = strlen(v9) - 1;
                  if ( v9[v23] == 47 )
                  {
                    v9[v23] = 0;
                    v24 = strlen(v9) - 1;
                    if ( v9[v24] == 47 )
                    {
                      v9[v24] = 0;
                      v25 = strlen(v9) - 1;
                      if ( v9[v25] == 47 )
                      {
                        v9[v25] = 0;
                        v26 = strlen(v9) - 1;
                        if ( v9[v26] == 47 )
                        {
                          v9[v26] = 0;
                          v27 = strlen(v9) - 1;
                          if ( v9[v27] == 47 )
                            v9[v27] = 0;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      sprintf(byte_C1E8, "%s\n", v9);
      if ( !regexec((const regex_t *)(v14 + 12), byte_C1E8, *(_DWORD *)(v14 + 44), v15, 0) )
      {
        (*(void (__fastcall **)(regmatch_t *))v14)(v15);
LABEL_46:
        free(v15);
        return;
      }
      free(v15);
      v14 = *(_DWORD *)(v14 + 48);
      if ( !v14 )
        goto LABEL_32;
    }
  }
  error_handler("NULL method_str");
}