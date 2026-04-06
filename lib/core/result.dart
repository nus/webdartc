/// A discriminated union representing either a successful value or an error.
sealed class Result<T, E> {
  const Result();

  bool get isOk => this is Ok<T, E>;
  bool get isErr => this is Err<T, E>;

  T get value => (this as Ok<T, E>).value;
  E get error => (this as Err<T, E>).error;

  R fold<R>({required R Function(T value) ok, required R Function(E error) err}) {
    final self = this;
    if (self is Ok<T, E>) return ok(self.value);
    return err((self as Err<T, E>).error);
  }

  Result<U, E> map<U>(U Function(T value) f) {
    final self = this;
    if (self is Ok<T, E>) return Ok(f(self.value));
    return Err((self as Err<T, E>).error);
  }

  Result<T, F> mapErr<F>(F Function(E error) f) {
    final self = this;
    if (self is Ok<T, E>) return Ok(self.value);
    return Err(f((self as Err<T, E>).error));
  }
}

final class Ok<T, E> extends Result<T, E> {
  @override
  final T value;
  const Ok(this.value);

  @override
  String toString() => 'Ok($value)';
}

final class Err<T, E> extends Result<T, E> {
  @override
  final E error;
  const Err(this.error);

  @override
  String toString() => 'Err($error)';
}
