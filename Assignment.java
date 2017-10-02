import java.math.BigInteger;
import java.util.Random;
import java.security.*;
import javax.crypto.*;
import java.io.File;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;


class Assignment{
        public static byte [] random128bit()
        {
            SecureRandom random = new SecureRandom(); //This class provides a cryptographically strong random number generator (RNG).
            byte[] nbyte = new byte[16];
            random.nextBytes(nbyte);

            return nbyte;


        }
        public static  BigInteger randomValue(int bits){

        Random rand = new Random();
        BigInteger  result = new BigInteger(bits, rand);
        return result;

    }
    public static BigInteger mod(BigInteger sum,BigInteger p)
    {
       // BigInteger bi = sum.remainder(p);
        //return bi;
        return sum.remainder(p);

    }
    public static BigInteger modexp(BigInteger base, BigInteger exp,BigInteger m)
    {
        BigInteger sum=BigInteger.ONE;
       
        //BigInteger index = new BigInteger("1");
        BigInteger zero = new BigInteger("0");
        BigInteger one = new BigInteger("1");
        if (exp.equals(zero))
            return one;
        if (exp.equals(one))
            return mod(base,m);

        // addition exponentiation
        while (!exp.equals(zero))
        {
            if (exp.and(one).equals(one))
                sum=mod(sum.multiply(base),m);
                exp = exp.shiftRight(1);
                base=mod(sum.multiply(base),m);

        }
        return sum;                             
    }
    public static BigInteger sharedsecrectKey(BigInteger base,BigInteger exp,BigInteger m)
    {
        return modexp(base,exp,m);
    }
    public static BigInteger publicKeyB(BigInteger gen,BigInteger prvKeyb,BigInteger modp)
    {
            return modexp(gen,prvKeyb,modp);
    }
    public static  byte [] sha256digest(BigInteger sharedkey)
    {
        
        
        try{
                MessageDigest md = MessageDigest.getInstance("SHA-256");

                 /*this should generate the 256-bit AES key k*/
                //Note that the result of the hash would also be arbitrary binary data, and if you want to represent that in a string, you should use base64 or hex.
                byte [] key= sharedkey.toByteArray(); 
                md.update(key); //Updates the digest using the specified array of bytes
                byte [] digestbuf = md.digest(); //Performs a final update on the digest using the specified array of bytes
                return digestbuf;
               
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;  

           
    }
    public static byte[] readContenttoByteArray(String file)
    {
       try
        {
            Path file_path = Paths.get(file);
            return Files.readAllBytes(file_path);
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

        return null;
        
    }
    public static byte [] encrypt_AES_CBC(byte [] sharedkey, byte [] file, byte []iv_value)
    {
        
        try{
            
            IvParameterSpec iv = new IvParameterSpec(iv_value);
            SecretKeySpec key = new SecretKeySpec(sharedkey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encrypted_file = cipher.doFinal(file);
            
            return encrypted_file;

    
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
        

    }
    public static byte [] padding(byte[] file, int blockSizeBits)
    {
            int blockbytes = blockSizeBits/8; // get bytes size
            int bytesremainder = file.length%blockbytes; // use the block bytes to get the remaing blocks left

            byte [] paddedfile =new byte[file.length+(blockbytes-bytesremainder)];

            

            for(int i=0; i<file.length; i++)
            {
                paddedfile[i]=file[i];
            } 
            paddedfile[file.length] = (byte)0x80; // Binary 10000000
            return paddedfile;  


    }
    public static String byteTohex(byte [] data)
    {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for(byte b: data)
        sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }


	public static void main(String [] args)
	{

        String  p_hex ="b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
        String  generator_hex ="44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
        String  pubkA_hex="5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d";
        
        BigInteger pvtKeyb = randomValue(1023);  
        BigInteger gen = new BigInteger(generator_hex,16); // converts the string to a decimal with base 16 becuase hex is a base 16
        BigInteger p =new BigInteger(p_hex,16);
        BigInteger pubKeyA=new BigInteger(pubkA_hex,16);
        

        
        BigInteger public_key_B= publicKeyB(gen,pvtKeyb,p);
        BigInteger sharedKeyA= sharedsecrectKey(pvtKeyb,pubKeyA,p);

        
        byte [] pubkeyB = public_key_B.toByteArray();
        byte iv_val [];
        iv_val=random128bit();

        byte [] aeskey = sha256digest(sharedKeyA);
        byte [] file = readContenttoByteArray(""); //C:/4 th year/crypto/Test.zip
        byte [] paddedfile= padding(file,128);
        byte [] encryptedAes = encrypt_AES_CBC(aeskey,paddedfile,iv_val); // encrypted data now in encryptdaes

        System.out.println();
        System.out.println("My public key B:");
        System.out.println(byteTohex(pubkeyB));


        System.out.println();
        System.out.println("My 128-bit Iv:");
        System.out.println(byteTohex(iv_val));


         
        /*System.out.println();
        System.out.println("AES_encrypted_file:");
        System.out.println(byteTohex(encryptedAes));*/

        System.out.println();
        System.out.println("AES key:");
        System.out.print(byteTohex(aeskey));


       
		//System.out.print("the private key is "+sharedKeyA);
        //System.out.println();
      
         
        // reading in file
        //specifies an initialization vector (IV), IV is an unpredictable random number used to make sure that when the same message is encrypted twice, the ciphertext always different
       

        
        
    
	}	
}
