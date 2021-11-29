require "digest" # para operaciones de hash
require "securerandom" # para generar random nonces when signing

# -------------------------
# SEC2P256k1Elliptic Curve Parameters 
# -------------------------
# y² = x³ + ax + b Para la curva secp256k1 a=0 y b=7 
$a = 0
$b = 7

# número primo para la operación módulo
$p = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1

# número de puntos de la curva (order) n
$n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

# punto generador de la curva G
$G = {
  x: 55066263022277343669578718895168534326250603453777594175500187360389116729240,
  y: 32670510020758816978083085130507043184471273380659243275938904335757337482424,
}

# ---------------
# Inverso modular de un punto a de la curva
# ---------------
def inverse(a, m = $p)
  m_orig = m         
  a = a % m if a < 0
  prevy, y = 0, 1
  while a > 1 # algoritmo de euclides extendido
    q = m / a
    y, prevy = prevy - q * y, y
    a, m = m % a, a
  end
  return y % m_orig
end

# ------
# Double: Sumar un punto a sí mismo (doblar). 
# ------
def double(point)
  # m = (3x₁² + a) / 2y₁
  m = ((3 * point[:x] ** 2 + $a) * inverse((2 * point[:y]), $p)) % $p

  # x = m² - 2x₁
  x = (m ** 2 - (2 * point[:x])) % $p

  # y = m * (x₁ - x) - y₁
  y = (m * (point[:x] - x) - point[:y]) % $p

  # Return Suma
  return { x: x, y: y }
end


# ---
# Add: Sumar dos punto de la curva
# ---
def add(point1, point2)
  # Si los puntos coinciden -> call double
  if point1 == point2
    return double(point1)
  end

  # pendiente m = (y₁ - y₂) / (x₁ - x₂)
  m = ((point1[:y] - point2[:y]) * inverse(point1[:x] - point2[:x], $p)) % $p

  # x = m² - x₁ - x₂
  x = (m ** 2 - point1[:x] - point2[:x]) % $p

  # y = m * (x₁ - x) - y₁
  y = ((m * (point1[:x] - x)) - point1[:y]) % $p

  # Return Suma
  return { x: x, y: y }
end

# --------
# Multiply: 
# Utilización de la operación "double and add" para realizar una multiplicación rápida por un entero
# --------
def multiply(k, point = $G)

  current = point

  # Conviertir el entero a su representación en bianrio
  binary = k.to_s(2)

  # duplicamos y sumamos
  binary.split("").drop(1).each do |char| # de izq a drcha ignorando el primier caracter bianrio
    # 0 = duplicamos
    current = double(current)

    # 1 = duplicamos y sumamos
    current = add(current, point) if char == "1"
  end

  # Return k*point
  current
end

# ----
# DIGITAL SIGNATURE
# ----
def sign(private_key, hash, nonce = nil)

  # Se genera un número aleatorio k entre [1…n-1] denominado nonce:   
  if nonce == nil
    loop do
      nonce = SecureRandom.hex(32).to_i(16)
      break if nonce < $n # Asegurarse que es menor al número de puntos de la curva
    end
  end

  # Se multiplica el nonce por el grupo generador G y se selecciona la coordenada x
  r = multiply(nonce)[:x] % $n

  # Se computa s = nonce⁻¹ * (hash + private_key * r) mod n
  s = (inverse(nonce, $n) * (hash + private_key * r)) % $n

  # El resultado de la firma son los valores r y s
  return { r: r, s: s }
end

# ------
# Verify Signature
# ------
def verify(public_key, signature, hash)
  # Computo (s⁻¹ * hash) G, siendo G el grupo generador
  point1 = multiply(inverse(signature[:s], $n) * hash)

  # Computo (s⁻¹ * r)Q , siendo Q la clave pública 
  point2 = multiply((inverse(signature[:s], $n) * signature[:r]), public_key)

  # Sumo ambos valores
  point3 = add(point1, point2)

  # Compruebo si el valor de r coincide con la coordenada x de point3 (la suma anterior)
  #return point3[:x] == signature[:r]
  return point3[:x]
end

# -------------------
# KEY GENERATION
# -------------------
# Clave privada generada aleatoriamente
private_key = "f94a840f1e1a901843a75dd07ffcc5c84478dc4f987797474c9393ac53ab55e6"

#Clave pública: public_key = private key * G
point = multiply(private_key.to_i(16), $G)

# Convertir Valores de la calve pública a HEX
x = point[:x].to_s(16).rjust(64, "0") 
y = point[:y].to_s(16).rjust(64, "0")

# Clave pública sin comprimir (coordenadas x e y) Se añade el prefijo 04 en este caso
public_key_uncompressed = "04" + x + y

# Clave pública comprimida (Se utiliza un prefijo para indicar si "y" es un valor par (02) o impar (04))
if (point[:y] % 2 == 0)
  public_key_compressed = "02" + x # y es par
else
  public_key_compressed = "03" + x # y es impar
end

puts "Clave Privada (d): "
puts private_key
puts ""
puts "Clave Pública (Q): "
print "  Componente x: "; puts x
print "  Componente y: "; puts y
puts ""
puts "Clave Pública (Q) en formato SIN COMPRIMIR: "
print "  " ; puts public_key_uncompressed
puts ""
puts "Clave pública (Q) en formato COMPRIMIDO: "
print "  " ; puts public_key_compressed
puts "" 
# -------------------
# DIGITAL SIGNATURE
# -------------------
message= "TFM Master Seguridad Informatica UNIR"
hash = Digest::SHA256.hexdigest(message)
sign_hash = sign(private_key.to_i(16), hash.to_i(16), nonce = nil)
r = sign_hash[:r].to_s(16).rjust(64, "0") 
s = sign_hash[:s].to_s(16).rjust(64, "0") 
# -------------------
# DIGITAL VERIFICATION
# -------------------
v = verify(point,sign_hash, hash.to_i(16))
v = v.to_s(16).rjust(64, "0") 

puts "Mensaje: " 
print "  " ; puts message
puts ""
puts "Hash del mensaje a firmar: " 
print "  " ; puts hash
puts ""
puts "Componentes Firma digital: "
print "  Componente r: "; puts r
print "  Componente s: "; puts s
puts "" 
puts "Valor de v calculado después de la verificación: "
print "  Componente v: "; puts v
puts "" 
  


#=> 024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1

# ------------------
# Sign A Transaction
# ------------------
# A basic structure for holding the transaction data
def tx(scriptsig)
  # Need to calculate a byte indicating the size of upcoming scriptsig in bytes (rough code but does the job)
  size = (scriptsig.length / 2).to_s(16).rjust(2, "0")

  # Raw unsigned transaction data with the scriptsig field (you need to know the correct position)
  return "0100000001b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b00000000#{size}#{scriptsig}ffffffff01983a0000000000001976a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac00000000"
end

# Private key and public key for the locked up bitcoins we want to spend
private_key = "f94a840f1e1a901843a75dd07ffcc5c84478dc4f987797474c9393ac53ab55e6" # sha256("learnmeabitcoin1")
public_key = "024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1"

# NOTE: Need to remove all existing signatures from the transaction data first if there are any

# Put original scriptpubkey as a placeholder in to the scriptsig for the input you want to sign (required)
scriptpubkey = "76a9144299ff317fcd12ef19047df66d72454691797bfc88ac" # just one input in this transaction
transaction = tx(scriptpubkey)

# Append sighash type to transaction data (required)
transaction = transaction + "01000000"

# Get a hash of the transaction data (because we sign the hash of data and not the actual data itself)
hash = Digest::SHA256.hexdigest(Digest::SHA256.digest([transaction].pack("H*")))

# Use elliptic curve mathematics to sign the hash using the private key and nonce
signature = sign(private_key.to_i(16), hash.to_i(16), 123456789) # using a fixed nonce for testing (unsafe)

# Use the low s value (BIP 62: Dealing with malleability)
if (signature[:s] > $n / 2)
  signature[:s] = $n - signature[:s]
end

# Encode the signature in to DER format (slightly awkward format used for signatures in bitcoin transactions)
r = signature[:r].to_s(16).rjust(64, "0")  # convert r to hexadecimal
s = signature[:s].to_s(16).rjust(64, "0")  # convert s to hexadecimal
r = "00" + r if (r[0, 2].to_i(16) >= 0x80) # prepend 00 if first byte is 0x80 or above (DER quirk)
s = "00" + r if (s[0, 2].to_i(16) >= 0x80) # prepend 00 if first byte is 0x80 or above (DER quirk)
der = ""                                   # string for holding our der encoding
r_len = (r.length / 2).to_s(16).rjust(2, "0") # get length of r (in bytes)

s_len = (s.length / 2).to_s(16).rjust(2, "0") # get length of s (in bytes)
der << "02" << r_len << r << "02" << s_len << s   # Add to DER encoding (0x20 byte indicates an integer type in DER)
der_len = (der.length / 2).to_s(16).rjust(2, "0") # get length of DER data (in bytes)
der = "30" + der_len + der # Final DER encoding (0x30 byte incatetes compound object type)

# Append sighashtype to the signature (required) (01 = ALL)
der = der + "01" # without it you get "mandatory-script-verify-flag-failed (Non-canonical DER signature) (code 16)"

# Contruct full unlocking script (P2PKH scripts need original public key the bitcoins were locked to): <size> {signature} <size> {public_key}
scriptsig = (der.length / 2).to_s(16) + der + (public_key.length / 2).to_s(16) + public_key

# Put the full scriptsig in to the original transaction data
transaction = tx(scriptsig)

# Show the signed transaction
#puts transaction #=> 0100000001b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b000000006a473044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb02201f40afd1627798ee8529095ca4b205498032315240ac322c9d8ff0f205a93a580121024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1ffffffff01983a0000000000001976a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac00000000

# Send the transaction in to the bitcoin network
# $ bitcoin-cli sendrawtransaction [raw transaction data]