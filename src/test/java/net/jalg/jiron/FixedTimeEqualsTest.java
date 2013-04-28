package net.jalg.jiron;

import static org.junit.Assert.*;

import org.junit.Test;

public class FixedTimeEqualsTest {

	@Test
	public void testFixedTimeEquals() {
		
		assertTrue(Jiron.fixedTimeEqual("",""));
		assertTrue(Jiron.fixedTimeEqual("x","x"));
		assertTrue(Jiron.fixedTimeEqual("foo","foo"));
		
		assertFalse(Jiron.fixedTimeEqual("f",""));
		assertFalse(Jiron.fixedTimeEqual("","f"));
		assertFalse(Jiron.fixedTimeEqual("foo",""));
		assertFalse(Jiron.fixedTimeEqual("","foo"));
		assertFalse(Jiron.fixedTimeEqual("foo","x"));
		assertFalse(Jiron.fixedTimeEqual("x","foo"));
		assertFalse(Jiron.fixedTimeEqual("foo","foo1"));
		assertFalse(Jiron.fixedTimeEqual("foo1","foo"));
		assertFalse(Jiron.fixedTimeEqual("foo","bar"));
		assertFalse(Jiron.fixedTimeEqual("foo2","foo1"));
		
	}
	
}
