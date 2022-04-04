<?php

// creamos nuestro secreto
$secret = 'bullcodeSecreto';

/// creamos la funcion que creara nuestro token

function createToken($secret){
    //Creamos el header de nuestro Tooken
    $header = json_encode(["type"=>'JWT',"alg"=>'HS256']);

    // CREAMOS EL PAYLOAD DEL TOKEN

    $payload = json_encode([
        'user_id'=>123,
        'name'=>'bullcode',
        'correo'=> 'bullcodeprogramacion@gmail.com',
        'iat'=>time(),
        'exp'=>time()+1800
    ]);

    /**
     * Codificamos nuestro header en string base64
     */

     $base64UrlHeader = str_replace('=','',strtr(base64_encode($header),'+/','-_'));

     // codificamos tambien nuestro payload
     $base64UrlPayload = str_replace('=','',strtr(base64_encode($payload),'+/','-_'));

     // ahora creamos el hash de la firma con el header y el payload codificados 
     //y nuestra clave secreta

     $signature = hash_hmac('sha256',$base64UrlHeader.'.'.$base64UrlPayload,$secret,true);

     // ahora codificamos nuestra firma en base64 tambien
     $base64UrlSignature = str_replace('=','',strtr(base64_encode($signature),'+/','-_'));

     // por ultimo montamos el JWT Y lo retornamos

     $jwt = $base64UrlHeader.".".$base64UrlPayload.".".$base64UrlSignature;
     return $jwt;
}

// ahora vamos a obtener nuestro token

//$token = createToken($secret);

// vamos a guardar nuestro token para probarlo
$token = "eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJ1c2VyX2lkIjoxMjMsIm5hbWUiOiJidWxsY29kZSIsImNvcnJlbyI6ImJ1bGxjb2RlcHJvZ3JhbWFjaW9uQGdtYWlsLmNvbSIsImlhdCI6MTY0OTA3ODg2OSwiZXhwIjoxNjQ5MDgwNjY5fQ.exYq1MLURy1ujpv5w-Jeu2Caq5hGIhNroEYI4lE7EDU";


// creamos una funcion para checkar el token

function checkToken($token,$secret){
    // hacemos un explode para obtener el header , payload y firma por separado

    $tks = explode('.',$token);
    
    // con la funcion list asignamos a las variables cada posicion del array
    list($head64,$payload64,$signature64) = $tks;
    // ahora utilizamos la funcion decode
    $signatureDecode = decode($signature64);
    $headDecode = json_decode(decode($head64));
    $payloadDecode = json_decode(decode($payload64));
    
    // checkamos que el token no ha caducado
    if(time()>$payloadDecode->exp) return 'El token ha expirado';

    /**
     * Si no ha expirado el token creamos una nueva firma con el head64 y payload64 para compararla 
     * con nuestra firma y ver que no esta manipulado nada
     */

     $signatureToCompare = hash_hmac('sha256',$head64.'.'.$payload64,$secret,true);

     // ahoracomparamos las dos firmas con la funcion y si son correctas damos el visto bueno
     if(!hash_equals($signatureToCompare,$signatureDecode)) return 'la firma no es valida';

     return 'token correcto';

}

// probamos nuestra funcion 

//echo checkToken($token,$secret);


// aqui vamos a crea otra funcion para decodificar correctamente el token
// ya que hemos reemplazado los = y demas simbolos

function decode($input){
    // buscamos los multiplos de 4 donde hemos reemplazado los iguales
    $remainder = strlen($input) % 4;
    if($remainder){
        $padlen = 4 - $remainder;
        // insertamos en su sitio correspondiente los signos =
        $input .= str_repeat('=',$padlen);
    }
    // aqui volvemos a invertir los simbolos de guion y guion bajo por el slash y la suma
    return base64_decode(strtr($input,'-_','+/'));
}


/// vamos a coger el token y vamos a manipularlo

function manipulacionToken($token){
    // sepramos el token y cogemos el payload
    $tks = explode('.',$token);
    list($head64,$payload64,$signature64) = $tks;
    $payloadDecode = json_decode(decode($payload64));
    // aqui tenemos informacion que podemos obtener pero vamosa manipularla
    $payloadManipulado = json_encode(
        [
            "user_id"=>1,
            "name" => "admin",
            "correo"=>"bullcodeprogramacion@gmail.com",
            "iat"=>time(),
            "exp"=>time()+1800
        ]
    );

    // ahora lo pasamos a base64
    $base64UrlPayload = str_replace('=','',strtr(base64_encode($payloadManipulado),'+/','-_'));

    // ahora montamos el token con el header y la firma que se supone que nop podemos manipularla ya que no sabemos el secret

    return $head64.".".$base64UrlPayload.".".$signature64;

}

// ahora manipulamos el token y lo checkamos

//echo manipulacionToken($token);

$tokenManipulado = 'eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJ1c2VyX2lkIjoxLCJuYW1lIjoiYWRtaW4iLCJjb3JyZW8iOiJidWxsY29kZXByb2dyYW1hY2lvbkBnbWFpbC5jb20iLCJpYXQiOjE2NDkwODAyMzUsImV4cCI6MTY0OTA4MjAzNX0.exYq1MLURy1ujpv5w-Jeu2Caq5hGIhNroEYI4lE7EDU';
echo checkToken($token,$secret);
?>
