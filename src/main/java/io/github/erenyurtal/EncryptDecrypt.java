package io.github.erenyurtal;

import java.io.*;

import java.security.SecureRandom;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;
import java.nio.file.Paths;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class EncryptDecrypt {

    // Register BouncyCastle as a security provider
    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static void encryptFile(String outputFile, String inputFile,
                                   String pubKeyFile, boolean armor, boolean withIntegrityCheck) throws IOException, PGPException {


        // Open output stream for encrypted data, wrap in ASCII armor if needed
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile));
             OutputStream out = armor
                     ? new ArmoredOutputStream(bos)
                     : bos;
             InputStream publicKeyInputStream = new BufferedInputStream(new FileInputStream(pubKeyFile))
        ) {

            // Decode and load public key ring collection
            PGPPublicKeyRingCollection pgpPublicKeys = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyInputStream), new JcaKeyFingerprintCalculator());

            // Iterate through key rings to find first encryption key
            PGPPublicKey pgpPublicKey = null;
            Iterator<PGPPublicKeyRing> keyRingIter = pgpPublicKeys.getKeyRings();

            outer:
            while (keyRingIter.hasNext()) {
                PGPPublicKeyRing keyRing =  keyRingIter.next();
                Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
                while (keyIter.hasNext()) {
                    PGPPublicKey key =  keyIter.next();
                    if (key.isEncryptionKey()) {
                        pgpPublicKey = key;
                        break outer;
                    }
                }
            }
            if (pgpPublicKey == null) {
                throw new PGPException("Encryption key not found in " + pubKeyFile);
            }

            // Compress and prepare the input file as a literal data packet
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            PGPCompressedDataGenerator comGen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
            PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
            File input = new File(inputFile);

            try (OutputStream compData = comGen.open(bOut);
                 OutputStream litOut = litGen.open(
                         compData,
                         PGPLiteralDataGenerator.BINARY,
                         input.getName(),
                         input.length(),
                         new java.util.Date());
                 FileInputStream inputStream = new FileInputStream(inputFile)
            ) {


                byte[] readBuf = new byte[1 << 13];
                int len;
                while ((len = inputStream.read(readBuf)) != -1) {
                    litOut.write(readBuf, 0, len);
                }
            }

            byte[] bytes = bOut.toByteArray();

            // Build encryption generator with selected algorithm and options
            PGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                    .setProvider("BC")
                    .setSecureRandom(new SecureRandom())
                    .setWithIntegrityPacket(withIntegrityCheck);

            // Set up encryptor: AES-256, integrity check if requested
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encryptorBuilder);
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey)
                    .setProvider("BC"));

            // Encrypt the literal data and write to output
            try(OutputStream cOut = encGen.open(out,bytes.length)) {
                cOut.write(bytes);
            }
        }
    }


    public static void decryptFile(String encryptedInputFile, String privateKeyFile,
                            char[] passphrase, String outputDir) throws IOException, PGPException, NullPointerException
    {

        // Open input streams for encrypted data and private key
        try(InputStream in = new BufferedInputStream(new FileInputStream(encryptedInputFile));
            InputStream privateKeyInputStream = PGPUtil.getDecoderStream(new BufferedInputStream(new FileInputStream(privateKeyFile)));
            InputStream decoderIn = PGPUtil.getDecoderStream(in);

        ){

            // Parse PGP objects to find encrypted data list
            JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(decoderIn);
            PGPEncryptedDataList encList = null;
            Object obj;
            while((obj = pgpObjectFactory.nextObject()) != null)
            {
                if(obj instanceof PGPEncryptedDataList)
                {
                    encList = (PGPEncryptedDataList) obj;
                    break;
                }
            }
            if(encList == null)
            {
                throw new PGPException("EncryptedDataList has not found");
            }

            // Load secret key ring and find matching secret key
            PGPSecretKeyRingCollection pgPrivateKeys = new PGPSecretKeyRingCollection(privateKeyInputStream,new JcaKeyFingerprintCalculator());

            // Find the secret key matching the encryption
            PGPSecretKey pgpSecretKeyData = null;
            Iterator<PGPSecretKeyRing> keyRingIterator = pgPrivateKeys.getKeyRings();

            outer:
            while(keyRingIterator.hasNext())
            {
             PGPSecretKeyRing keyRing = keyRingIterator.next();
             Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
             while(keyIter.hasNext())
             {
                 PGPSecretKey key = keyIter.next();
                 if(key.getPublicKey().isEncryptionKey())
                 {
                     pgpSecretKeyData = key;
                     break outer;
                 }
             }
            }

            if (pgpSecretKeyData == null) {
                throw new PGPException("Secret key for decryption not found.");
            }

            JcePBESecretKeyDecryptorBuilder decryptBuilder = new JcePBESecretKeyDecryptorBuilder()
                    .setProvider("BC");

            // Decrypt the secret key with passphrase
            PBESecretKeyDecryptor decrypt = decryptBuilder.build(passphrase);
            PGPPrivateKey privateKey = pgpSecretKeyData.extractPrivateKey(decrypt);
            if (privateKey == null) {
                throw new PGPException("Private key not found in the provided secret key file.");
            }


            // Find encrypted data packet and decrypt session data
            PGPPublicKeyEncryptedData pbe = null;
            for (PGPEncryptedData enc : encList) {
                if (enc instanceof PGPPublicKeyEncryptedData) {
                    pbe = (PGPPublicKeyEncryptedData) enc;
                    break;
                }
            }

            JcePublicKeyDataDecryptorFactoryBuilder publicKeyDataDecryptBuilder = new JcePublicKeyDataDecryptorFactoryBuilder()
                    .setProvider("BC");

            // Decrypt the session and obtain the data stream
            PublicKeyDataDecryptorFactory factory = publicKeyDataDecryptBuilder.build(privateKey);
            InputStream clear = pbe.getDataStream(factory);
            if(clear == null)
            {
                throw new PGPException("Unable to access decrypted data. Either the passphrase is incorrect or the encrypted data is invalid.");

            }

            // Decompress the data
            JcaPGPObjectFactory pgpObjectFactory1 = new JcaPGPObjectFactory(clear);
            Object o;
            PGPCompressedData compData = null;
            while((o = pgpObjectFactory1.nextObject()) != null) if (o instanceof PGPCompressedData) {
                compData = (PGPCompressedData) o;
                break;
            }
            if (compData == null) {
                throw new PGPException("No compressed data found. Are you sure this is a valid PGP file? 🤨");
            }

            InputStream uncompressed = compData.getDataStream();
            if (uncompressed == null) {
                throw new PGPException("Unable to decompress the encrypted data. The input may be corrupted or not properly compressed.");
            }

            // Extract literal data (original file)
            JcaPGPObjectFactory pgpObjectFactory3 = new JcaPGPObjectFactory(uncompressed);
            Object msg;
            PGPLiteralData ltData = null;
            while (((msg = pgpObjectFactory3.nextObject()) != null))
            {
                if(msg instanceof PGPLiteralData)
                {
                    ltData = (PGPLiteralData) msg;
                    break;
                }
            }


            // Write decrypted data to file
            String outputFileName = ltData.getFileName();
            if (outputFileName == null || outputFileName.isBlank()) {
                outputFileName = "decrypted_output.pgp";
            }
            String safeName = Paths.get(outputFileName).getFileName().toString();

            File outDir = new File(outputDir);
            if (!outDir.exists()) outDir.mkdirs();
            File outFile = new File(outDir, safeName);


            try(InputStream literal = ltData.getDataStream();
            OutputStream decFile = new BufferedOutputStream(new FileOutputStream(outFile))
            ) {

                byte[] writeBuf = new byte[1 << 13];
                int len;
                while ((len = literal.read(writeBuf)) != -1) {
                    decFile.write(writeBuf, 0, len);
                }
            }

            // Verify integrity if available
            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    throw new PGPException("Integrity check failed: the file may have been tampered with.");
                }
            } else {
                System.out.println("Warning: No integrity protection (MDC). The file was decrypted, but its authenticity cannot be verified.");
            }
        }

    }

}
