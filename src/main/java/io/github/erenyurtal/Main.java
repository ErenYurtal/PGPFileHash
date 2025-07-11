package io.github.erenyurtal;

import java.io.Console;
import java.nio.file.Paths;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("=== PGP File Encryptor/Decryptor ===");
            System.out.println("1. Encrypt a file");
            System.out.println("2. Decrypt a file");
            System.out.println("q. Quit");
            System.out.print("Select an option (1/2/q): ");
            String choice = scanner.nextLine();

            if (choice.equals("1")) {

                System.out.print("Enter path of the file to encrypt: ");
                String inputFile = scanner.nextLine();

                System.out.print("Enter path to the public key file (e.g. keys/public.asc): ");
                String pubKey = scanner.nextLine();

                System.out.print("Enter the directory where the encrypted file should be saved: ");
                String outputDir = scanner.nextLine();

                System.out.print("Enter the name for the encrypted file (e.g. secret.pgp): ");
                String outputName = scanner.nextLine();

                String fullOutputPath = Paths.get(outputDir, outputName).toString();
                EncryptDecrypt.encryptFile(fullOutputPath, inputFile, pubKey, true, true);
                System.out.println("File encrypted successfully: " + fullOutputPath);

            } else if (choice.equals("2")) {

                System.out.print("Enter path of the file to decrypt: ");
                String encryptedFile = scanner.nextLine();

                System.out.print("Enter path to the private key file (e.g. keys/private.asc): ");
                String privKey = scanner.nextLine();

                Console console = System.console();
                if (console == null) {
                    throw new RuntimeException("Console not available. Are you running inside an IDE?");
                }
                char[] pass = console.readPassword("Enter the private key passphrase: ");

                System.out.print("Enter the directory where the decrypted file should be saved: ");
                String outputDir = scanner.nextLine();

                EncryptDecrypt.decryptFile(encryptedFile, privKey, pass, outputDir);
                System.out.println("File decrypted successfully into: " + outputDir);

            } else if (choice.equals("q")) {
                System.out.println("Exiting program...");
                System.exit(0);

            } else {
                System.out.println("Invalid selection. Please enter 1, 2, or q.");
            }
        }
    }
}