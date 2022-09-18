package br.unb.cic.mop.jca.util;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class DefineAlgorithms {

    static private final Properties prop;

    static
    {
        prop= new Properties();
        if (null != System.getProperty("javamop.properties")){
            try {
                System.out.println(Files.newInputStream(Paths.get(System.getProperty("javamop.properties"))));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            try (InputStream input = Files.newInputStream(Paths.get(System.getProperty("javamop.properties")))) {
                // load a properties file
                prop.load(input);
            } catch (IOException ex) {
                System.out.println("It was not possible read the file. Using default properties.");
            }
        }
    }

    public static List<String> getValidCypherModes() {
        List<String> modes;

        if (null != prop.getProperty("validCyphers")) {
            String[] strings = prop.getProperty("validCyphers").split(",");
            modes = Arrays.asList((strings));
        } else {
            modes = Arrays.asList("CBC", "CCM", "GCM", "PCBC", "CTR", "CTS", "CFB", "OFB");
        }
        return modes;
    }

    public static List<String> getRSAECBPaddings() {
        List<String> rsaECBPaddings;
        String[] strings;

        if (null != prop.getProperty("AECBPaddings")) {
            strings = prop.getProperty("AECBPaddings").split(",");
        } else {
            strings = new String[]{"NoPadding", "PKCS1Padding",
                    "OAEPWithMD5AndMGF1Padding", "OAEPWithSHA-224AndMGF1Padding",
                    "OAEPWithSHA-256AndMGF1Padding", "OAEPWithSHA-384AndMGF1Padding",
                    "OAEPWithSHA-512AndMGF1Padding"};
        }

        rsaECBPaddings = Arrays.stream(strings).map(String::toUpperCase).collect(Collectors.toList());

        return rsaECBPaddings;
    }

    public static HashMap<String, List<String>> getCommonPaddings() {
        HashMap<String, List<String>> padding = new HashMap<>();
        if (null != prop.getProperty("commonPaddings")) {
            String[] strings = prop.getProperty("commonPaddings").split(",");
            List<String> commonPaddings = Arrays.asList((strings));
            padding.put("GCM", commonPaddings);
            padding.put("CTR", commonPaddings);
            padding.put("CTS", commonPaddings);
            padding.put("CFB", commonPaddings);
            padding.put("OFB", commonPaddings);
            padding.put("CCM",commonPaddings);

        } else {
            padding.put("GCM", Arrays.asList("", "NOPADDING"));
            padding.put("CTR", Arrays.asList("", "NOPADDING"));
            padding.put("CTS", Arrays.asList("", "NOPADDING"));
            padding.put("CFB", Arrays.asList("", "NOPADDING"));
            padding.put("OFB", Arrays.asList("", "NOPADDING"));
            padding.put("CCM",Arrays.asList("", "NOPADDING"));
            System.out.println("commonPaddings = " + Arrays.asList("", "NOPADDING"));
        }

        // CBC like Paddings => CBC PCBC
        if (null != prop.getProperty("cbcLikePaddings")) {
            String[] strings = prop.getProperty("cbcLikePaddings").split(",");
            List<String> cbcLikePaddings = Arrays.asList((strings));
            padding.put("CBC", cbcLikePaddings);
            padding.put("PCBC", cbcLikePaddings);
        } else {
            padding.put("CBC", Arrays.asList("PKCS5PADDING", "ISO10126PADDING", "PKCS5PADDING"));
            padding.put("PCBC", Arrays.asList("PKCS5PADDING", "ISO10126PADDING", "PKCS5PADDING"));

        }

        return padding;
    }

}