# laravel_middleware

#Route/api
Route::prefix('themansa/v1')->group(function (){

    Route::get('Roles',[ApiController::class,'Roles']);
    Route::get('sectors',[ApiController::class,'sectors']);
    Route::post('register',[ApiController::class,'register']);
    Route::post('login',[ApiController::class,'login']);

    Route::middleware(['auth:sanctum','checkuser'])->group(function(){
        //startup links goes here
        
    });
    Route::middleware(['auth:sanctum','IsInvestor'])->group(function(){
        // investor routes goes here 
    });

});

#middleware role
public function handle(Request $request, Closure $next)
    {
        $user = Auth::user();
        if(!Auth::check()){
            abort(403,"YOU ARE NOT AUTHORIZED");
        }
        if($user->role === "1")
        {
            return $next($request); 
        }
       abort(403,"YOU ARE NOT ABLE AUTHORIZED");
    }
    
    #ApiController
    public function register(Request $request)
    {
       
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|unique:email',
            'password' => 'required',
        ]);
 
        if ($validator->fails()) {
            $errors = $validator->errors();
            return response(['message'=>'Registration failed due to some incorrect inputs','Errorinput' => $errors]);
        }
        $user_data = $request->all();
        $user_data['password'] = Hash::make($request->password);
        $user = User::create($user_data);
        $success['token'] = $user->createToken('token')->plainTextToken;
        $success['user'] = $user;
        return $success;
    }
    public function login(Request $request)
    {
        if(Auth::attempt($request->only('email', 'password')))
        {
            $user = Auth::user();
            $success['_token'] = $user->createToken('token')->plainTextToken;
            $success['user'] = $user;
            return $success;
        }
        return response(['message'=>'Invalid credentials']);
    }
