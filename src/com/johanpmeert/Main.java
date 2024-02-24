package com.johanpmeert;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.image.BufferedImage;
import java.awt.print.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Hashtable;

import com.github.sarxos.webcam.Webcam;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.bitcoinj.core.Utils.sha256hash160;

public class Main implements Printable, ActionListener {

    private static JLabel hexRandomValueLabel, WIFValueLabel, bitcoinAddressValueLabel;
    private static GenerateKeys generatedKeys;
    public static Logger logger = LoggerFactory.getLogger(Main.class);

    public enum Actions {
        PRINT, REGENERATE, SHOW_QR, QUIT, COPY_WIF, COPY_BTC, WEBCAM, PASTE_SEED
    }

    public static void main(String[] args) {
        // bitcoin address generation
        generatedKeys = new GenerateKeys();
        // Create UI
        UIManager.put("swing.boldMetal", Boolean.FALSE);
        JFrame f = new JFrame("Bitcoin paper wallet printer using SecureRandom or WebCAM picture");
        f.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });
        f.setSize(750, 200);
        // Create buttons
        JButton printButton = new JButton("Print paper wallet");
        printButton.setBounds(10, 120, 135, 30);
        printButton.addActionListener(new Main());
        printButton.setActionCommand(Actions.PRINT.name());
        f.add(printButton);
        JButton regenerateButton = new JButton("Regenerate keys");
        regenerateButton.setBounds(160, 120, 125, 30);
        regenerateButton.addActionListener(new Main());
        regenerateButton.setActionCommand(Actions.REGENERATE.name());
        f.add(regenerateButton);
        JButton qrButton = new JButton("Show PublicKey QR");
        qrButton.setBounds(300, 120, 150, 30);
        qrButton.addActionListener(new Main());
        qrButton.setActionCommand(Actions.SHOW_QR.name());
        f.add(qrButton);
        JButton quitButton = new JButton("Quit");
        quitButton.setBounds(600, 120, 100, 30);
        quitButton.addActionListener(new Main());
        quitButton.setActionCommand(Actions.QUIT.name());
        f.add(quitButton);
        JButton pasteHexSeed = new JButton("PASTE");
        pasteHexSeed.setBounds(625, 10, 75, 25);
        pasteHexSeed.addActionListener(new Main());
        pasteHexSeed.setActionCommand(Actions.PASTE_SEED.name());
        f.add(pasteHexSeed);
        JButton copyWifButton = new JButton("COPY");
        copyWifButton.setBounds(625, 40, 75, 25);
        copyWifButton.addActionListener(new Main());
        copyWifButton.setActionCommand(Actions.COPY_WIF.name());
        f.add(copyWifButton);
        JButton copyBtcButton = new JButton("COPY");
        copyBtcButton.setBounds(625, 70, 75, 25);
        copyBtcButton.addActionListener(new Main());
        copyBtcButton.setActionCommand(Actions.COPY_BTC.name());
        f.add(copyBtcButton);
        // WebCam button
        Webcam webcam = Webcam.getDefault();
        JButton webcamButton = new JButton("WebCAM");
        webcamButton.setBounds(465, 120, 100, 30);
        webcamButton.addActionListener(new Main());
        webcamButton.setActionCommand(Actions.WEBCAM.name());
        f.add(webcamButton);
        if (webcam == null) {
            webcamButton.setEnabled(false);
        } else {
            webcam.close();
        }
        // Create Text labels
        JLabel hexRandomLabel = new JLabel("Hex random seed:");
        hexRandomLabel.setBounds(10, 10, 100, 20);
        f.add(hexRandomLabel);
        hexRandomValueLabel = new JLabel(generatedKeys.hexRandom);
        hexRandomValueLabel.setBounds(115, 10, 500, 20);
        f.add(hexRandomValueLabel);
        JLabel WIFLabel = new JLabel("Bitcoin private key (WIF):");
        WIFLabel.setBounds(10, 40, 140, 20);
        f.add(WIFLabel);
        WIFValueLabel = new JLabel(generatedKeys.privateKey);
        WIFValueLabel.setBounds(150, 40, 400, 20);
        f.add(WIFValueLabel);
        JLabel bitcoinAddressLabel = new JLabel("Bitcoin address (Segwit P2SH):");
        bitcoinAddressLabel.setBounds(10, 70, 170, 20);
        f.add(bitcoinAddressLabel);
        bitcoinAddressValueLabel = new JLabel(generatedKeys.bitcoinAddress);
        bitcoinAddressValueLabel.setBounds(180, 70, 400, 20);
        f.add(bitcoinAddressValueLabel);
        // Finalize layout
        f.setLayout(null);
        f.setVisible(true);
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals(Actions.PRINT.name())) {
            PrinterJob job = PrinterJob.getPrinterJob();
            job.setPrintable(this);
            boolean ok = job.printDialog();
            if (ok) {
                try {
                    job.print();
                } catch (PrinterException ex) {
                    ex.printStackTrace();
                }
            }
        } else if (e.getActionCommand().equals(Actions.REGENERATE.name())) {
            generatedKeys = new GenerateKeys();
            updateLabels();
        } else if (e.getActionCommand().equals(Actions.QUIT.name())) {
            System.exit(0);
        } else if (e.getActionCommand().equals(Actions.COPY_WIF.name())) {
            StringSelection sS = new StringSelection(generatedKeys.privateKey);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(sS, null);
        } else if (e.getActionCommand().equals(Actions.COPY_BTC.name())) {
            StringSelection sS = new StringSelection(generatedKeys.bitcoinAddress);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(sS, null);
        } else if (e.getActionCommand().equals(Actions.PASTE_SEED.name())) {
            String hexSeed = getClipboardContents();
            if ((hexSeed != null) && (hexSeed.length() == 64) && (hexSeed.matches("-?[0-9a-fA-F]+"))) {
                generatedKeys = new GenerateKeys(hexSeed.toUpperCase());
                updateLabels();
            }
        } else if (e.getActionCommand().equals(Actions.SHOW_QR.name())) {
            // generate new popup window with the Public Key QR-CODE
            JFrame qrFrame = new JFrame("Public Key QR code");
            qrFrame.getContentPane().setLayout(new FlowLayout());
            try {
                qrFrame.getContentPane().add(new JLabel(new ImageIcon(createQRImage(generatedKeys.bitcoinAddress, 350))));
            } catch (WriterException ex) {
                throw new RuntimeException(ex);
            }
            qrFrame.pack();
            qrFrame.setLocation(800, 100);
            qrFrame.setVisible(true);
        } else if (e.getActionCommand().equals(Actions.WEBCAM.name())) {
            // get VGA picture from webcam
            Webcam webcam2 = Webcam.getDefault();
            webcam2.setViewSize(new Dimension(640, 480));
            webcam2.open();
            BufferedImage image = webcam2.getImage();
            webcam2.close();
            // save to disk with random name
            // get the SHA-256 hash from that file
            SecureRandom sr = new SecureRandom();
            String name = "webcam_" + sr.nextInt(0, 2147483647) + ".png";
            String shaString;
            try {
                ImageIO.write(image, "PNG", new File(name));
                // the file is small at about 300-700kB so we read-in the complete file in memory
                byte[] data = Files.readAllBytes(Paths.get(name));
                byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
                shaString = byteArrayToHexString(hash);
            } catch (IOException | NoSuchAlgorithmException ex) {
                throw new RuntimeException(ex);
            }
            // generate the bitcoin key using the calculated 32 byte SHA-256 hash as the private key
            generatedKeys = new GenerateKeys(shaString);
            updateLabels();
            // show the picture
            JFrame webcamFrame = new JFrame("WebCAM picture");
            webcamFrame.getContentPane().setLayout(new FlowLayout());
            webcamFrame.getContentPane().add(new JLabel(new ImageIcon(image)));
            webcamFrame.pack();
            webcamFrame.setLocation(100, 250);
            webcamFrame.setVisible(true);
        }
    }

    public static void updateLabels() {
        hexRandomValueLabel.setText(generatedKeys.hexRandom);
        WIFValueLabel.setText(generatedKeys.privateKey);
        bitcoinAddressValueLabel.setText(generatedKeys.bitcoinAddress);
    }

    public int print(Graphics g, PageFormat pf, int page) {
        switch (page) {
            case 0 -> {
                Graphics2D g2d = (Graphics2D) g;
                g.setFont(new Font("Monospaced", Font.PLAIN, 8));
                g2d.translate(pf.getImageableX(), pf.getImageableY());
                BufferedImage QRimageWIF = null, QRimageBitcoinAddress = null, RandomImage1 = null, RandomImage2 = null;
                try {
                    QRimageWIF = createQRImage(generatedKeys.privateKey, 120);
                    QRimageBitcoinAddress = createQRImage(generatedKeys.bitcoinAddress, 120);
                    RandomImage1 = createRandomImage(125, 150);
                    RandomImage2 = createRandomImage(100);
                } catch (WriterException e) {
                    e.printStackTrace();
                }
                g.drawImage(QRimageBitcoinAddress, 20, 50, 110, 110, null);
                g.drawString("PUBLIC ADDRESS", 40, 150);
                g.drawString(generatedKeys.bitcoinAddress, 5, 45);
                g.drawString(generatedKeys.bitcoinAddress, 5, 165);
                g.drawImage(RandomImage1, 190, 30, 125, 150, null);
                g.drawImage(RandomImage2, 355, 55, 100, 100, null);
                g.drawImage(QRimageWIF, 460, 45, 120, 120, null);
                g.drawString(generatedKeys.privateKey, 322, 50);
                g.drawString(generatedKeys.privateKey, 322, 165);
                g.drawLine(0, 10, 325, 10);
                g.drawLine(325, 10, 335, 30);
                g.drawLine(335, 30, 570, 30);
                g.drawLine(0, 200, 325, 200);
                g.drawLine(325, 200, 335, 180);
                g.drawLine(335, 180, 570, 180);
                g.drawLine(340, 60, 340, 145);
                g.drawLine(185, 20, 185, 190);
                return PAGE_EXISTS;
            }
            case 1 -> {
                Graphics2D g2d = (Graphics2D) g;
                g.setFont(new Font("Monospaced", Font.PLAIN, 8));
                g2d.translate(pf.getImageableX(), pf.getImageableY());
                BufferedImage RandomRect = null;
                try {
                    RandomRect = createRandomImage(120, 20);
                } catch (WriterException e) {
                    e.printStackTrace();
                }
                g.drawLine(260, 10, 570, 10);
                g.drawLine(260, 200, 570, 200);
                g.drawLine(260, 10, 260, 200);
                g.drawLine(570, 10, 570, 200);
                g.drawLine(300, 80, 530, 80);
                g.drawLine(300, 130, 530, 130);
                g.drawLine(300, 180, 530, 180);
                g.drawString("Private key (WIF)", 140, 80);
                g.drawString("inside here", 150, 100);
                g.setFont(new Font("Monospaced", Font.BOLD, 10));
                g.drawString("KEEP HIDDEN", 140, 140);
                g.drawString("BITCOIN PAPER WALLET (SEGWIT)", 325, 30);
                g.drawImage(RandomRect, 120, 40, 120, 20, null);
                g.drawImage(RandomRect, 120, 155, 120, 20, null);
                return PAGE_EXISTS;
            }
            default -> {
                return NO_SUCH_PAGE;
            }
        }
    }

    private static BufferedImage createQRImage(String qrCodeText, int size) throws WriterException {
        Hashtable<EncodeHintType, ErrorCorrectionLevel> hintMap = new Hashtable<>();
        hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.H);
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix byteMatrix = qrCodeWriter.encode(qrCodeText, BarcodeFormat.QR_CODE, size, size, hintMap);
        int matrixSize = byteMatrix.getWidth();
        BufferedImage image = new BufferedImage(matrixSize, matrixSize, BufferedImage.TYPE_INT_RGB);
        image.createGraphics();
        Graphics2D graphics = (Graphics2D) image.getGraphics();
        graphics.setColor(Color.WHITE);
        graphics.fillRect(0, 0, matrixSize, matrixSize);
        graphics.setColor(Color.BLACK);
        for (int i = 0; i < matrixSize; i++) {
            for (int j = 0; j < matrixSize; j++) {
                if (byteMatrix.get(i, j)) {
                    graphics.fillRect(i, j, 1, 1);
                }
            }
        }
        return image;
    }

    private static BufferedImage createRandomImage(int size) throws WriterException {
        return createRandomImage(size, size);
    }

    private static BufferedImage createRandomImage(int size1, int size2) throws WriterException {
        BufferedImage image = new BufferedImage(size1, size2, BufferedImage.TYPE_INT_RGB);
        image.createGraphics();
        Graphics2D graphics = (Graphics2D) image.getGraphics();
        graphics.setColor(Color.WHITE);
        graphics.fillRect(0, 0, size1, size2);
        graphics.setColor(Color.BLACK);
        SecureRandom sr = new SecureRandom();
        for (int i = 0; i < size1; i++) {
            for (int j = 0; j < size2; j++) {
                if (sr.nextBoolean()) {
                    graphics.fillRect(i, j, 1, 1);
                }
            }
        }
        return image;
    }

    public static class GenerateKeys {
        public String hexRandom, privateKey, bitcoinAddress;
        private final static String UPPER_LIMIT = "F".repeat(56);  // safe upper limit for validity of ECDSA

        public GenerateKeys() {
            byte[] random32bytes = new byte[32];
            SecureRandom sr = new SecureRandom();  // using cryptographic safe random function
            String hexTest;
            do {
                sr.nextBytes(random32bytes);
                hexTest = byteArrayToHexString(random32bytes);
            }
            while (hexTest.substring(0, 55).equals(UPPER_LIMIT));
            hexRandom = hexTest;
            CalcKey();
        }

        public GenerateKeys(String hexRandomString) {
            if (hexRandomString.length() == 64) {
                hexRandom = hexRandomString;
            } else {
                throw new IllegalArgumentException("Given string must be 32 bytes long, but is " + hexRandomString.length() / 2 + " long");
            }
            if (hexRandomString.substring(0, 55).equals(UPPER_LIMIT))
                throw new IllegalArgumentException("Given string is outside of valid ECDSA allowed range");
            CalcKey();
        }

        private void CalcKey() {
            privateKey = Base58CheckEncode("80" + hexRandom + "01"); // private key in WIF format
            String compressedPubKey = privToCompressedPublic(hexRandom);
            String rawCompressedBitcoinAddress = hashShaRipemd(compressedPubKey);
            String redeemScript = "0014" + rawCompressedBitcoinAddress;  // = OP_PUSH hashedCompressedPubKey
            String hashedRedeemScript = hashShaRipemd(redeemScript);
            bitcoinAddress = Base58CheckEncode("05" + hashedRedeemScript); // public bitcoin address, Segwit style
            logger.info(bitcoinAddress);
        }

    }

    private static String Base58CheckEncode(String address) {
        String base58encoded = "";
        byte[] checksum1 = hexStringToByteArray(address);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] checksum2 = digest.digest(checksum1);  // first SHA256 hash
            byte[] checksum3 = digest.digest(checksum2);  // second SHA256 hash
            String checksum4 = byteArrayToHexString(checksum3);
            address = address + checksum4.substring(0, 8);  // take the first 4 bytes of the double hash and add them at the end of the original hex string
            base58encoded = Base58.encode(hexStringToByteArray(address));  // encode with base58
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return base58encoded;
    }

    private static byte[] privToCompressedPublic(byte[] address) {
        ECKey key = ECKey.fromPrivate(address);
        return key.getPubKey();
    }

    private static String privToCompressedPublic(String address) {
        return byteArrayToHexString(privToCompressedPublic(hexStringToByteArray(address)));
    }

    private static byte[] hashShaRipemd(byte[] address) {
        return sha256hash160(address);
    }

    private static String hashShaRipemd(String address) {
        return byteArrayToHexString(hashShaRipemd(hexStringToByteArray(address)));
    }

    private static byte[] hexStringToByteArray(String hex) {
        hex = hex.length() % 2 != 0 ? "0" + hex : hex;
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hex.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    private static String byteArrayToHexString(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private String getClipboardContents() {
        String result = "";
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable contents = clipboard.getContents(null);
        boolean hasTransferableText = (contents != null) && contents.isDataFlavorSupported(DataFlavor.stringFlavor);
        if (hasTransferableText) {
            try {
                result = (String) contents.getTransferData(DataFlavor.stringFlavor);
            } catch (UnsupportedFlavorException | IOException ex) {
                ex.printStackTrace();
            }
        }
        return result;
    }

}