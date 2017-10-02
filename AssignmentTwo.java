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



class AssignmentTwo
{
	static BigInteger d;
	static BigInteger x;
	static BigInteger y;
	
	static BigInteger primeP; 
	static BigInteger primeQ; 

	static BigInteger primeValue()
	{
		Random rand = new Random();
        BigInteger  result;
        result= BigInteger.probablePrime(512,rand);
        return result;
	}
	static BigInteger product(BigInteger x,BigInteger y)
	{
		return x.subtract(BigInteger.ONE).multiply(y.subtract(BigInteger.ONE));
	}
	static BigInteger phi_n()
	{
		BigInteger one = new BigInteger("1");
		BigInteger n;
		BigInteger exponent = new BigInteger("65537");
		
		primeP= primeValue();
		primeQ= primeValue();
		n= product(primeP,primeQ);
		

		while(!gcd(n,exponent).equals(one))
		{
			 primeP= primeValue();
			 primeQ= primeValue();

			 n=product(primeP,primeQ);

			 if(gcd(n,exponent).equals(one))
			 {
			 	return n;
			 }
		}
		if(gcd(n,exponent).equals(one))
		{
			 	return n;
		}
		else
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
	public static  BigInteger sha256digest(byte [] file)
    {
    		BigInteger hashedfile =BigInteger.ONE;
        try{
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                hashedfile= new BigInteger(1,md.digest(file));; 
               
                
                
               
        }catch(Exception e){
            e.printStackTrace();
        }
        return hashedfile;  

           
    }
	static  BigInteger extecludiean(BigInteger e,BigInteger n)
	{
		
		BigInteger zero =new BigInteger("0");

		if(n.equals(zero))
		{
			d=e;
			x=BigInteger.ONE;
			y=BigInteger.ZERO;
		}
		else
		{
			extecludiean(n,e.mod(n));
			BigInteger temp=x;
			x=y;
			y=temp.subtract((e.divide(n)).multiply(y));
			
		}
		return x;

	}
	public static BigInteger mod(BigInteger sum,BigInteger p)
    {
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
	static BigInteger modInverse(BigInteger a,BigInteger m)
	{
		BigInteger xVal=extecludiean(a,m);
		return((xVal.mod(m)).add(m)).mod(m);
		
	}
	static BigInteger gcd(BigInteger n, BigInteger m)
	{
		BigInteger zero = new BigInteger("0");
		if (m.equals(zero))  
			return n;
		else
			return gcd(m,n.mod(m));
	}
	static BigInteger decryptionExpo()
	{
		BigInteger e =new BigInteger("65537");
		BigInteger phi = phi_n();
		BigInteger d=modInverse(e,phi);
		return d;

	}
	static byte [] decryption(BigInteger digest)
	{
		
		BigInteger dexpo = decryptionExpo();
		BigInteger d_q,d_p,q_inv,m1,m2,h,h1,m,sum;

		d_p= dexpo.mod(primeP);
		d_q=dexpo.mod(primeQ);
		q_inv=modInverse(primeQ,primeP);

		m1=modexp(digest,d_p,primeP);
		m2=modexp(digest,d_q,primeQ);
		h=modInverse(q_inv,m1.subtract(m2));
		h1=h.mod(primeP);
		sum=h.multiply(primeQ);
		m=m2.add(sum);

		byte [] result= m.toByteArray();
		return result;
	}
	public static String byteTohex(byte [] data)
    {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for(byte b: data)
        sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
    public static void ntoHex()
	{
		BigInteger pi=phi_n();
		byte [] nVal=pi.toByteArray();
		System.out.print(byteTohex(nVal));
	}
	public static void main(String [] args)
	{
		
		byte [] file = readContenttoByteArray("AssignmentTwo.zip");
	
		BigInteger digestFile = sha256digest(file);
		byte [] decryption_applied=decryption(digestFile);
		String result =byteTohex(decryption_applied);
		

		System.out.print("Digitially signed code in hex: ");
		System.out.println(result);
		System.out.println();
		System.out.println("N in hex: ");
		System.out.println();
		ntoHex();	
	}
}

// code does not seem to be able to handle negative mod numbers to be fixed later