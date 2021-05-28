package ysoserial;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.Callable;
import org.nustaq.serialization.FSTObjectOutput;

public class FSTSerializer implements Callable<byte[]> {

	private final Object object;

	public FSTSerializer(Object object) {
		this.object = object;
	}

	public byte[] call() throws Exception {
		return serialize(object);
	}

	public static byte[] serialize(final Object obj) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		serialize(obj, out);
		return out.toByteArray();
	}

	public static void serialize(final Object obj, final OutputStream out) throws IOException {
		FSTObjectOutput fout = new FSTObjectOutput(out);
		fout.writeObject(obj);
		fout.close();
	}

}
