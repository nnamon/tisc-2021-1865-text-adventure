package com.mad.hatter;

import com.mad.hatter.proto.Cake;
import org.nustaq.serialization.FSTConfiguration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;
import java.util.InputMismatchException;
import java.io.IOException;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.io.FileUtils;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.gson.Gson;


/**
 * Hello! I'm your friendly party organiser and cake designer!
 *
 */
public class App {

    static FSTConfiguration conf = FSTConfiguration.createDefaultConfiguration();

    public static void main(String[] args) throws IOException {
        // Get the secret bytes.
        byte[] secret = get_secret();

        // Get the invitation code.
        String invitation_code = System.getenv("INVITATION_CODE").trim();

        // Initialise some common variables.
        Scanner scanner = new Scanner(System.in);

        // Create a cake with some simple defaults.
        Cake.Builder cakep = Cake.newBuilder()
            .setName("A Plain Cake")
            .setCandles(31337)
            .setFlavour("Vanilla");

        // Print the Banner
        System.out.println("Welcome to the March Hare's and Mad Hatter's Tea Party.");
        System.out.println("It's your Unbirthday! Hopefully...");
        System.out.println("Before we let you in, though... Why is a raven like a writing desk?");

        // Get the invitation code and check it.
        System.out.print("Invitation Code: ");
        String user_invite = scanner.next().trim();
        if (!user_invite.equals(invitation_code)) {
            System.out.println("That invitation code was wrong! Begone and good day!");
            return;
        }
        System.out.println("Correct! Welcome!");
        System.out.println("Come on into the party! But first, let's design you a cake!");

        // Run the main loop.
        boolean running = true;

        try {
            while (running) {
                running = evaluate(scanner, cakep, secret);
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }

        System.out.println("Hope you had fun! Bad day!");
    }

    @SuppressWarnings("unchecked")
    public static boolean evaluate(Scanner scanner, Cake.Builder cakep, byte[] secret) {
        System.out.println("\n[Cake Designer Interface v4.2.1]");
        System.out.println("  1. Set Name.");
        System.out.println("  2. Set Candles.");
        System.out.println("  3. Set Caption.");
        System.out.println("  4. Set Flavour.");
        System.out.println("  5. Add Firework.");
        System.out.println("  6. Add Decoration.\n");
        System.out.println("  7. Cake to Go.");
        System.out.println("  8. Go to Cake.");
        System.out.println("  9. Eat Cake.\n");
        System.out.println("  0. Leave the Party.");
        System.out.println("\n[Your cake so far:]\n");
        System.out.println(cakep);
        System.out.print("Choice: ");

        int choice = scanner.nextInt();
        boolean running = true;

        switch (choice) {
            case 0:
                running = false;
                break;
            case 1:
                scanner.nextLine();
                String name = scanner.nextLine().trim();
                cakep.setName(name);
                System.out.println("Name set!");
                break;
            case 2:
                int candles = scanner.nextInt();
                cakep.setCandles(candles);
                System.out.println("Number of candles set!");
                break;
            case 3:
                scanner.nextLine();
                String caption = scanner.nextLine().trim();
                cakep.setCaption(caption);
                System.out.println("Caption set!");
                break;
            case 4:
                scanner.nextLine();
                String flavour = scanner.nextLine().trim();
                cakep.setFlavour(flavour);
                System.out.println("Flavour set!");
                break;
            case 5:
                if (cakep.getFireworksCount() < 5) {
                    System.out.println("Which firework do you wish to add?\n");
                    System.out.println("  1. Firecracker.");
                    System.out.println("  2. Roman Candle.");
                    System.out.println("  3. Firefly.");
                    System.out.println("  4. Fountain.");
                    System.out.print("\nFirework: ");

                    int firework_choice = scanner.nextInt();
                    Firework firework = new Firework();

                    switch (firework_choice) {
                        case 1:
                            firework = new Firecracker();
                            break;
                        case 2:
                            firework = new RomanCandle();
                            break;
                        case 3:
                            firework = new Firefly();
                            break;
                        case 4:
                            firework = new Fountain();
                            break;
                        default:
                            break;
                    }
                    byte[] firework_data = conf.asByteArray(firework);
                    cakep.addFireworks(ByteString.copyFrom(firework_data));
                    System.out.println("Firework added!");
                } else {
                    System.out.println("You already have too many fireworks!");
                }
                break;
            case 6:
                if (cakep.getDecorationsCount() < 5) {
                    System.out.println("Which decoration do you wish to add?\n");
                    for (Cake.Decoration deco : Cake.Decoration.values()) {
                        System.out.println("  - " + deco);
                    }
                    System.out.print("\nDecoration: ");
                    String deco_choice = scanner.next().trim();
                    Cake.Decoration resolved = Cake.Decoration.valueOf(deco_choice);
                    cakep.addDecorations(resolved);
                    System.out.println("Decoration added!");
                } else {
                    System.out.println("You already have too many decorations!");
                }
                break;
            case 7:

                byte[] cake_data = cakep.build().toByteArray();
                byte[] cake_b64 = Base64.encodeBase64(cake_data);

                try {
                    MessageDigest md = MessageDigest.getInstance("SHA-512");
                    byte[] combined = new byte[secret.length + cake_b64.length];
                    System.arraycopy(secret, 0, combined, 0, secret.length);
                    System.arraycopy(cake_b64, 0, combined, secret.length, cake_b64.length);
                    byte[] message_digest = md.digest(combined);
                    HashMap<String, String> hash_map = new HashMap<String, String>();
                    hash_map.put("digest", Hex.encodeHexString(message_digest));
                    hash_map.put("cake", Hex.encodeHexString(cake_b64));
                    String output = (new Gson()).toJson(hash_map);
                    System.out.println("Here's your cake to go:");
                    System.out.println(output);
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("What how can this be?!?");
                }

                break;
            case 8:

                System.out.print("Please enter your saved cake: ");

                scanner.nextLine();
                String saved = scanner.nextLine().trim();

                try {

                    HashMap<String, String> hash_map = new HashMap<String, String>();
                    hash_map = (new Gson()).fromJson(saved, hash_map.getClass());
                    byte[] challenge_digest = Hex.decodeHex(hash_map.get("digest"));
                    byte[] challenge_cake_b64 = Hex.decodeHex(hash_map.get("cake"));
                    byte[] challenge_cake_data = Base64.decodeBase64(challenge_cake_b64);

                    MessageDigest md = MessageDigest.getInstance("SHA-512");
                    byte[] combined = new byte[secret.length + challenge_cake_b64.length];
                    System.arraycopy(secret, 0, combined, 0, secret.length);
                    System.arraycopy(challenge_cake_b64, 0, combined, secret.length,
                            challenge_cake_b64.length);
                    byte[] message_digest = md.digest(combined);

                    if (Arrays.equals(message_digest, challenge_digest)) {
                        Cake new_cakep = Cake.parseFrom(challenge_cake_data);
                        cakep.clear();
                        cakep.mergeFrom(new_cakep);
                        System.out.println("Cake successfully gotten!");
                    }
                    else {
                        System.out.println("Your saved cake went really bad...");
                    }

                } catch (DecoderException e) {
                    System.out.println("What what what?!?");
                } catch (InvalidProtocolBufferException e) {
                    System.out.println("No bueno!");
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("What how can this be?!?");
                }

                break;
            case 9:
                System.out.println("You eat the cake and you feel good!");

                for (Cake.Decoration deco : cakep.getDecorationsList()) {
                    if (deco == Cake.Decoration.TINY_HELLO_KITTY) {
                        running = false;
                        System.out.println("A tiny Hello Kitty figurine gets lodged in your " +
                                "throat. You get very angry at this and storm off.");
                        break;
                    }
                }

                if (cakep.getFireworksCount() == 0) {
                    System.out.println("Nothing else interesting happens.");
                } else {
                    for (ByteString firework_bs : cakep.getFireworksList()) {
                        byte[] firework_data = firework_bs.toByteArray();
                        Firework firework = (Firework) conf.asObject(firework_data);
                        firework.fire();
                    }
                }
                break;
            default:
                System.out.println("That was not one of the options! Please listen!");
                break;
        }

        return running;
    }

    public static byte[] get_secret() throws IOException {
        // Read the secret from /home/hatter/secret.
        byte[] data = FileUtils.readFileToByteArray(new File("/home/hatter/secret"));
        if (data.length != 32) {
            System.out.println("Secret does not match the right length!");
        }
        return data;
    }
}
